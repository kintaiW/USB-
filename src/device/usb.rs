extern crate libusb;
extern crate crypto;

// use std::slice;
use std::fmt;
use std::time::Duration;
// use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian, LittleEndian, ByteOrder};

use crate::cipher::sm4::SM4;
use crate::cipher::cipher::Cipher;
use crypto::digest::Digest;
use crypto::sha1::Sha1;

static VENDOR: u16 = 0x2fd0;
static PRODUCT: u16 = 0x1002;
// #[macro_export]
// macro_rules! b2l_16 {
//     ( $x:expr ) => {
//        [($x >> 8) as u8, $x as u8]
//     };
// }

#[derive(Debug)]
struct Endpoint {
    config: u8,
    iface: u8,
    setting: u8,
    address: u8
}

pub struct USBDevice {
    vid: u16,
    pid: u16
}

impl USBDevice {
    pub fn new(a: u16, b: u16) -> USBDevice {
        USBDevice { vid: a, pid: b}
    }
    //根据vec容量装满，最大256字节
    //CMD:10 = Tag:1 Length:2 (CLA:1 INS:1 P1:1 P2:1 Le:3)
    //Feedback: = Tag:1 Length:2 (Data:len SW1:1 SW2:1)
    pub fn skf_random(&self, vec: &mut Vec<u8>) {

        let mut length = vec.capacity();
        if length == 0 {
            return;
        } else if length > 256 {
            length = 256;
        }

        let mut cmd: [u8; 10] = [ 0x12, 0x00, 0x07, 0x80, 0x50, 0x0, 0x0, 0x00, 0x00, 0x00 ];
        //cmd Le
        // let temp = length.to_le_bytes();
        cmd[8] = length.to_le_bytes()[1];
        cmd[9] = length.to_le_bytes()[0];

        invoke_fn(self.vid, self.pid, &cmd, vec);
    }

    pub fn skf_devinfo(devinfo: &mut DevInfo) {
        let cmd: [u8; 10] = [ 0x12, 0x00, 0x07, 0x80, 0x04, 0x0, 0x0, 0x00, 0x00, 0x00 ];

        let mut out = Vec::with_capacity(512);
        invoke_fn(VENDOR, PRODUCT, &cmd, &mut out);
        // println!("{}", out.len());

        let (head, body, _tail) = unsafe {out.align_to::<DevInfo>()};
        assert!(head.is_empty(), "Data was not aligned");
        let info = &body[0];
        // devinfo = info.to_be();

        devinfo.algsyncap = info.algsyncap.to_be();
        devinfo.algasyncap = info.algasyncap.to_be();
        devinfo.alghashcap = info.alghashcap.to_be();
        devinfo.devauthalgid = info.devauthalgid.to_be();
        devinfo.totalspace = info.totalspace.to_be();
        devinfo.freespace = info.freespace.to_be();
        devinfo.maxapdudatalen = info.maxapdudatalen.to_be();
        devinfo.userauthmethod = info.userauthmethod.to_be();
        devinfo.devicetype = info.devicetype.to_be();
        devinfo.maxfilenum = info.maxfilenum.to_be();
    }
    //step.2: support id use skf_sign_with_id fn
    pub fn skf_sign(&self, auth_info: &DevAuthInfo, data: &[u8], out: &mut Vec<u8>) {
        let mut container_id: [u8; 2] = [0x0, 0x0];
        // let user_id: [u8; 16] = [ 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38];

        USBDevice::skf_dev_auth(self, auth_info);

        let mut app_info = AppInfo::default();
        USBDevice::skf_open_app(self, auth_info, &mut app_info);
        // println!("{:02x?}", app_info);

        // USBDevice::skf_verify_pin(self, auth_info, &app_info, 0x0);
        USBDevice::skf_verify_pin(self, auth_info, &app_info, 0x1);

        USBDevice::skf_open_container(self, auth_info, &app_info, &mut container_id);
        // println!("{:02x?}", container_id);

        USBDevice::skf_eccsign(self, &app_info, container_id, 0x02,  data, out);
        // println!("{:02x?}", out);

        USBDevice::skf_clear_state(self, &app_info);
        USBDevice::skf_close_app(self, &app_info);
    }
    pub fn skf_verify() {

    }

    pub fn export_public_key(&self, auth_info: &DevAuthInfo, public_key: &mut Vec<u8>, type_id: u8) {
        USBDevice::skf_dev_auth(self, auth_info);

        let mut app_info = AppInfo::default();
        USBDevice::skf_open_app(self, auth_info, &mut app_info);
        // println!("{:02x?}", app_info);

        // USBDevice::skf_verify_pin(self, auth_info, &app_info, 0x0);
        USBDevice::skf_verify_pin(self, auth_info, &app_info, 0x1);

        let mut container_id: [u8; 2] = [0x0, 0x0];
        USBDevice::skf_open_container(self, auth_info, &app_info, &mut container_id);
        
        USBDevice::skf_export_public_key(self, &app_info, container_id, public_key, type_id);

        USBDevice::skf_clear_state(self, &app_info);
        USBDevice::skf_close_app(self, &app_info);
    }    

    pub fn skf_dev_auth(&self, auth_info: &DevAuthInfo) {//GMT_INS_DEV_AUTH = 0x10
        let cmd: [u8; 10] = [0x12,0x00,0x17,0x80,0x10,0x0,0x0,0x00,0x00,0x10];
        let auth_key = auth_info.auth_key.as_bytes();
 
        let mut auth_data = [0x0; 16];
        let mut random = Vec::with_capacity(16);
        USBDevice::skf_random(self, &mut random);
        // &auth_data[0..8].copy_from_slice(&random);//？
        &auth_data.copy_from_slice(&random);
        let mut buf = Vec::with_capacity(16 + 10);//auth_data + cmd

        let cipher = SM4::new_from_ref(auth_key);
        cipher.encrypt(&mut buf, &auth_data).unwrap();

        buf.append(&mut cmd.to_vec());

        let mut out = Vec::with_capacity(512);// no use
        invoke_fn(self.vid, self.pid, &buf, &mut out);
    }

    pub fn skf_open_app(&self, auth_info: &DevAuthInfo, app_info: &mut AppInfo) {//GMT_INS_OPEN_APP = 
        let mut cmd: [u8; 10] = [0x12,0x00,0x00,0x80,0x26,0x0,0x0,0x00,0x00,0x00];
        let cmd_le: [u8; 2] = [0x00, 0xa];
        let app_name = auth_info.app_name.as_bytes();
        let app_name_len = auth_info.app_name_len;

        let cmd_len = 0x7 + app_name_len + 0x2;
        cmd[2] = cmd_len.to_le_bytes()[0];
        cmd[9] = app_name_len.to_le_bytes()[0];

        let mut buf = Vec::with_capacity(cmd_len + 3);
        buf.append(&mut cmd.to_vec());
        buf.append(&mut app_name.to_vec());
        buf.append(&mut cmd_le.to_vec());

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &buf, &mut out);

        let (head, body, _tail) = unsafe {out.align_to::<AppInfo>()};
        assert!(head.is_empty(), "Data was not aligned");
        let info = &body[0];

        app_info.dw_create_file_rights = info.dw_create_file_rights.to_be();
        app_info.by_max_container_num = info.by_max_cert_num;
        app_info.by_max_cert_num = info.by_max_cert_num;
        app_info.w_max_file_num = info.w_max_file_num.to_be();
        app_info.w_app_id = info.w_app_id.to_be();
    }

    pub fn skf_verify_pin(&self, auth_info: &DevAuthInfo, app_info: &AppInfo, pin_type: u8) {
        let mut cmd: [u8; 12] = [0x12,0x00,0x19,0x80,0x18,0x0,0x0,0x00,0x00,0x12,0x00,0x00];

        cmd[6] = pin_type;
        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];

        let mut auth_data: [u8; 16] = [0x0; 16];
        auth_data[0] = 0x80;
        auth_data[1] = 0x0;
        auth_data[11] = 0x80;

        let mut random = Vec::with_capacity(8);
        USBDevice::skf_random(self, &mut random);
        &auth_data[2..10].copy_from_slice(&random);

        let mut hasher = Sha1::new();
        hasher.input(auth_info.ad_pin.as_bytes());


        let mut ukey_enckey = [0x0; 20];
        let mut auth_cipher = Vec::with_capacity(16);
        hasher.result(&mut ukey_enckey);
        let cipher = SM4::new_from_ref(&ukey_enckey[..16]);
        cipher.encrypt(&mut auth_cipher, &auth_data).unwrap();

        let mut buf = Vec::with_capacity(12+16);
        buf.append(&mut cmd.to_vec());
        buf.append(&mut auth_cipher);

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &buf, &mut out);
    }
    
    pub fn skf_open_container(&self, auth_info: &DevAuthInfo, app_info: &AppInfo, container_id: &mut [u8]) {
        let mut cmd: [u8; 12] = [0x12,0x00,0x00,0x80,0x42,0x0,0x0,0x00,0x00,0x12,0x00,0x00];
        let cmd_le: [u8; 2] = [0x00, 0x02];

        cmd[2] = 7 + 2 + auth_info.con_name_len.to_le_bytes()[0] + 2;
        cmd[9] = 2 + auth_info.con_name_len.to_le_bytes()[0];
        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];

        let mut buf = Vec::with_capacity(10 + 2 + auth_info.con_name_len + 2);
        buf.append(&mut cmd.to_vec());
        buf.append(&mut auth_info.con_name.as_bytes().to_vec());
        buf.append(&mut cmd_le.to_vec());

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &buf, &mut out);

        container_id[0] = out[0].to_be();
        container_id[1] = out[1].to_be();
    }

    pub fn skf_eccsign(&self, app_info: &AppInfo, container_id: [u8; 2], type_id: u8, data: &[u8], signdata: &mut Vec<u8>) {
        let mut cmd: [u8; 14] = [0x12,0x00,0x00,0x80,0x74,type_id,0x0,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
        let cmd_end: [u8; 2] = [0x0, 0x0];

        let len = 14 + data.len() + 2;
        cmd[1] = (len - 3).to_le_bytes()[1];
        cmd[2] = (len - 3).to_le_bytes()[0];
        cmd[8] = (len - 10 - 2).to_le_bytes()[1];
        cmd[9] = (len - 10 - 2).to_le_bytes()[0];
        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];
        cmd[12] = container_id[0];
        cmd[13] = container_id[1];

        let mut buf = Vec::with_capacity(len);
        buf.append(&mut cmd.to_vec());
        buf.append(&mut data.to_vec());
        buf.append(&mut cmd_end.to_vec());
        

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &buf, &mut out);

        assert!(out.len() == 68, "out length should be eq 68 usize");
        signdata.extend_from_slice(&out[4..]);
    }

    pub fn skf_clear_state(&self, app_info: &AppInfo) {
        let mut cmd: [u8; 12] = [0x12,0x00,0x09,0x80,0x1c,0x0,0x0,0x00,0x00,0x02,0x00,0x00];
        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];
   
        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &cmd, &mut out);
    }

    pub fn skf_close_app(&self, app_info: &AppInfo) {
        let mut cmd: [u8; 12] = [0x12,0x00,0x09,0x80,0x28,0x0,0x0,0x00,0x00,0x02,0x00,0x00];
        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &cmd, &mut out);
    }

    pub fn skf_export_public_key(&self, app_info: &AppInfo, container_id: [u8; 2], public_key: &mut Vec<u8>, type_id: u8) {
        let mut cmd: [u8; 16] = [0x12,0x00,0x0d,0x80,0x88,type_id,0x0,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00];

        cmd[10] = app_info.w_app_id.to_le_bytes()[1];
        cmd[11] = app_info.w_app_id.to_le_bytes()[0];
        cmd[12] = container_id[0];
        cmd[13] = container_id[1];

        let mut out = Vec::with_capacity(512);
        invoke_fn(self.vid, self.pid, &cmd, &mut out);

        if out.len()>= 4 {
            public_key.extend_from_slice(&out[4..]);
        }

    }

}

#[derive(Debug)]
struct Version {
    major: u8,
    minor: u8
}

#[repr(C)]
#[derive(Debug)]
pub struct DevInfo {
    version:        Version,
    _version:       Version,
    manufacturer:   [u8; 64],
    issuer:         [u8; 64],
    label:          [u8; 32],
    serialnumber:   [u8; 32],
    hwversion:      Version,
    firmware:       Version,
    algsyncap:      u32,
    algasyncap:     u32,
    alghashcap:     u32,
    devauthalgid:   u32,
    totalspace:     u32,
    freespace:      u32,
    maxapdudatalen: u16,
    userauthmethod: u16,
    devicetype:     u16,
    maxcontainernum:u8,
    maxcertnum:     u8,
    maxfilenum:     u16,
    reserved:       [u8; 54]
}

impl Default for DevInfo {
    fn default() -> DevInfo {
        DevInfo {
            version:        Version { major: 0x0, minor: 0x0},
            _version:       Version { major: 0x0, minor: 0x0},
            manufacturer:   [0x0; 64],
            issuer:         [0x0; 64],
            label:          [0x0; 32],
            serialnumber:   [0x0; 32],
            hwversion:      Version { major: 0x0, minor: 0x0},
            firmware:       Version { major: 0x0, minor: 0x0},
            algsyncap:      0x0,
            algasyncap:     0x0,
            alghashcap:     0x0,
            devauthalgid:   0x0,
            totalspace:     0x0,
            freespace:      0x0,
            maxapdudatalen: 0x0,
            userauthmethod: 0x0,
            devicetype:     0x0,
            maxcontainernum:0x0,
            maxcertnum:     0x0,
            maxfilenum:     0x0,
            reserved:       [0x0; 54]
        }
    }
}
//TODO:补充DevInfo结构体 显示内容
impl fmt::Display for DevInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Struct Version: {} {}\n", self.version.major, self.version.minor);
        write!(f, "Specification Version: {} {}", self._version.major, self._version.minor);
        write!(f, "Specification Version: {} {}", self._version.major, self._version.minor)
    }
}

// pub struct DevAuthInfo {
//     auth_key: [u8; 16],
//     auth_key_len: u8,
//     app_name: [u8; 32],
//     app_name_len: u8,
//     con_name: [u8; 34],
//     con_name_len: u8,
//     ad_pin: [u8; 16],
//     ad_pin_len: u8,
//     us_pin: [u8; 16],
//     us_pin_len: u8
// }

#[derive(Clone)]
pub struct DevAuthInfo {
    pub auth_key: String,
    pub auth_key_len: usize,
    pub app_name: String,
    pub app_name_len: usize,
    pub con_name: String,
    pub con_name_len: usize,
    pub ad_pin: String,
    pub ad_pin_len: usize,
    pub us_pin: String,
    pub us_pin_len: usize
}

impl Default for DevAuthInfo {
    fn default() -> DevAuthInfo {
        DevAuthInfo {
            auth_key: String::from("1122334455667788"),
            auth_key_len: 16,
            app_name: String::from("osrapp"),
            app_name_len: 6,
            con_name: String::from("osr"),
            con_name_len: 3,
            ad_pin: String::from("123456"),
            ad_pin_len: 6,
            us_pin: String::from("123456"),
            us_pin_len: 6
        }
    }
}

#[repr(C, packed)]
// #[derive(Debug)]
pub struct AppInfo {
	dw_create_file_rights: u32,//在该应用下创建文件和容器的权限
	by_max_container_num: u8,//指定应用可支持的最大容器数量
	by_max_cert_num: u8,//指定应用可支持的最大证书数量
	w_max_file_num: u16,//指定应用可支持的最大文件数量
	w_app_id: u16//返回的应用 ID，用于标识已打开的应用，后续操作可通过此 ID 引用打开的应用
}

impl Default for AppInfo {
    fn default() -> AppInfo {
        AppInfo {
            dw_create_file_rights: 0x0,
            by_max_container_num: 0x0,
            by_max_cert_num: 0x0,
            w_max_file_num: 0x0,
            w_app_id: 0x0
        }
    }
}

// unsafe fn deserialize_struct<T>(src: Vec<u8>) -> T {
//     std::ptr::read(src.as_ptr() as *const _)
// }

fn invoke_fn(vid: u16, pid: u16, cmd: &[u8], out: &mut Vec<u8>) {
    let mut buf: [u8; 512] = [0x0; 512];
    let timeout = Duration::from_secs(2);
    match libusb::Context::new() {
        Ok(mut context) => {
            match libusb::Context::open_device_with_vid_pid(&mut context, vid, pid) {
                Some(mut handle) => trans_bulk(&mut handle, &cmd, &mut buf, timeout),
                None => println!("could not find device {:04x}:{:04x}", vid, pid)
            }
        },
        Err(e) => {
            panic!("could not initialize libusb: {}", e)
        }

    };

    //Le: big ocnvert little
    let len = u32::from_le_bytes([buf[2], buf[1], 0x0, 0x0]);
    // Le:len = [data:retlen SW1:1 SW2:1]
    let retlen = len - 2;
    //find data length end index
    //let start_index = 3;
    let end_index = (3 + retlen) as usize;

    out.extend_from_slice(&buf[3..end_index]);
    // println!("{:02x?}", out);
}

fn trans_bulk(handle: &mut libusb::DeviceHandle, cmd: &[u8], buf: &mut [u8], timeout: Duration) {
    let scsicmd_read: [u8; 31] =
    [
        0x55,0x53,0x42,0x43,// U S B C
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,
        0x00,
        0x10,
        0xFE,
        0x02,
        0x00,
        0x00,0x00,
        0x00,0x00,
        0x00,0x0,
        0x00,0x00,
        0x00,0x00,
        0x00,0x00,0x00
    ];
    
    let scsicmd_send: [u8; 31]=
    [
        0x55,0x53,0x42,0x43,// U S B C
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,
        0x00,
        0x10,
        0xFE,
        0x01,
        0x47,
        0x4D,0x43,
        0x41,0x50,
        0x49,0x44,
        0x46,0x53,
        0x00,0x00,
        0x00,0x00,0x00
    ];

    let endpoint_in = Endpoint {
        config: 1,
        iface: 0,
        setting: 0,
        address: 0x81
    }; 

    let endpoint_out = Endpoint {
        config: 1,
        iface: 0,
        setting: 0,
        address: 0x01
    }; 
  
    let mut vec1: [u8; 512] = [0x0; 512];
    let mut vec2: [u8; 512] = [0x0; 512];

    match configure_endpoint(handle, &endpoint_out) {
        Ok(_) => match handle.write_bulk(endpoint_out.address, &scsicmd_send, timeout) {
            Ok(_) => match handle.write_bulk(endpoint_out.address, cmd, timeout) {
                Ok(_) => match handle.read_bulk(endpoint_in.address, &mut vec1, timeout) {
                    Ok(_) => match handle.write_bulk(endpoint_out.address, &scsicmd_read, timeout) {
                        Ok(_) => match handle.read_bulk(endpoint_in.address, buf, timeout) {
                            Ok(_) => {
                                // println!("0x{:02x?}", buf);
                                match handle.read_bulk(endpoint_in.address, &mut vec2, timeout) {
                                    Ok(_) => {},
                                    Err(err) => println!("could not read from endpoint: {}", err)
                                }
                            },
                            Err(err) => println!("could not read from endpoint: {}", err)
                        },
                        Err(err) => println!("could not write to endpoint: {}", err) 
                    },
                    Err(err) => println!("could not read from endpoint: {}", err)
                },
                Err(err) => println!("could not write to endpoint: {}", err)    
            },
            Err(err) => println!("could not write to endpoint: {}", err)
        },
        Err(err) => println!("could not configure endpoint: {}", err)
    }
}

fn configure_endpoint<'a>(handle: &'a mut libusb::DeviceHandle, endpoint: &Endpoint) -> libusb::Result<()> {
    handle.set_active_configuration(endpoint.config)?;
    handle.claim_interface(endpoint.iface)?;
    handle.set_alternate_setting(endpoint.iface, endpoint.setting)?;
    Ok(())
}

