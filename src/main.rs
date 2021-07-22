use clap::{Arg, App, SubCommand};

mod cipher;
mod device;
pub use device::usb::{USBDevice, DevInfo, DevAuthInfo};

pub use device::usb_test::{libusb_info, list_devices, read_devices};

fn hex_match_list(a: u8) -> u8 {
    match Some(a) {
        Some(0x30) => return 0x00,
        Some(0x31) => return 0x01,
        Some(0x32) => return 0x02,
        Some(0x33) => return 0x03,
        Some(0x34) => return 0x04,
        Some(0x35) => return 0x05,
        Some(0x36) => return 0x06,
        Some(0x37) => return 0x07,
        Some(0x38) => return 0x08,
        Some(0x39) => return 0x09,
        Some(0x61) => return 0x0a,
        Some(0x62) => return 0x0b,
        Some(0x63) => return 0x0c,
        Some(0x64) => return 0x0d,
        Some(0x65) => return 0x0e,
        Some(0x66) => return 0x0f,
        __         => panic!("请输入正确的<vid>、<pid>,参考 -v 2fd0 -p 1002 或者 -v=2fd0 -p=1002"), //?
    }
}

//TODO: &str 转化为 u16
fn str_to_u16(value: &str) -> Result<u16, std::io::Error> {
    let len = value.len();
    let mut index = -1;
    if len == 4 {
        index = 0;
    }
    if len == 6 {
        index = 2;
    }

    if index == -1 {
        panic!("u16 类型输入格式错误！")
    }

    let s = value.to_lowercase();
    let bytes = s.as_bytes();

    let v0: u8 = hex_match_list(bytes[0]);
    let v1 = hex_match_list(bytes[1]);
    let v2 = hex_match_list(bytes[2]);
    let v3 = hex_match_list(bytes[3]);

    let a0: u8 = v0 << 4 | v1 as u8;
    let a1: u8 = v2 << 4 | v3;

    let ret: u16 = u16::from_be_bytes([a0, a1]);
    Ok(ret)
}

fn main() {
    embed_resource::compile("./icon.rc");

    // usb_export_publickey(0x2fd0, 0x1002, String::from("12345678"));

    let matches = App::new("纽创信安USB检测工具")
        .version("0.1.0")
        .author("Huang xintai <xintai.huang@osr-tech.com>")
        .about("参考GM/T 0017-2012 《智能密码钥匙 密码应用接口数据格式规范》标准检测USB设备")
        .arg(Arg::with_name("vid")
                 .short("v")
                 .long("vid")
                 .takes_value(true)
                 .help("idVendor, 默认: 2fd0")) 
        .arg(Arg::with_name("pid")
                 .short("p")
                 .long("pid")
                 .takes_value(true)
                 .help("idProduct, 默认: 1002"))
        .arg(Arg::with_name("length")
                 .short("l")
                 .long("length")
                 .takes_value(true)
                 .help("length, 默认：0；最大：256"))  
        .arg(Arg::with_name("pin")
                 .long("pin")
                 .takes_value(true)
                 .help("用户PIN码, 默认: 123456"))                 
        .subcommand(SubCommand::with_name("test")
            .about("测试指令")
            // .arg(Arg::with_name())
            // .args_from_usage("-v, --vid=[vid] 'idVendor'")
            // .args_from_usage("-p, --pid=[pid] 'idProduct'")
            .subcommands( vec![
                SubCommand::with_name("info").about("获取libusb库信息"),
                SubCommand::with_name("list").about("获取USB设备列表详细信息"),
                SubCommand::with_name("read").about("读取USB设备")]))
        .subcommand(SubCommand::with_name("usb")
            .about("USB调试")
            .subcommands( vec![
                SubCommand::with_name("random").about("获取USB随机数，请使用OPTIONS:<length>指定随机数长度"),
                SubCommand::with_name("devinfo").about("获取USB设备信息，请使用OPTIONS:<VID>、<PID>指定需要打开的设备"),
                SubCommand::with_name("publickey").about("获取USB设备公钥，请使用OPTIONS:<VID>、<PID>指定需要打开的设备")]))
        .get_matches();     

        //设置默认值
        let mut vendor_id: u16 = 0x2fd0;
        let mut product_id: u16 = 0x1002;
        let mut length: usize = 0;
        let mut user_pin: String = String::from("123456");

        if let Some(vid) = matches.value_of("vid") {
            vendor_id = str_to_u16(vid).unwrap();
            println!("vid: {:04x}", vendor_id);
        }

        if let Some(pid) = matches.value_of("pid") {
            product_id = str_to_u16(pid).unwrap();
            println!("pid: {:04x}", product_id);
        }

        if let Some(len) = matches.value_of("length") {
            length = len.parse::<usize>().unwrap();
        }

        if let Some(pin) = matches.value_of("pin") {
            user_pin = String::from(pin);
            println!("user pin: {}", user_pin);
        }
        
        if let Some(matches) = matches.subcommand_matches("test") {
            match matches.subcommand_name() {
                Some("info") => libusb_info(),
                Some("list") => list_devices().unwrap(),
                Some("read") => read_devices(vendor_id, product_id),
                _            => {println!("no match!")},
            }
        }

        if let Some(matches) = matches.subcommand_matches("usb") {
            match matches.subcommand_name() {
                Some("random") => {
                    let d = USBDevice::new(0x2fd0, 0x1002);
                    let mut random = Vec::with_capacity(length);
                    d.skf_random(&mut random);
                    println!("{:02x?}", random);
                }
                Some("devinfo") => {
                    let mut devinfo = DevInfo::default();
                    USBDevice::skf_devinfo(&mut devinfo);
                    println!("Display: {}", devinfo);
                }
                Some("publickey") => {
                    usb_export_publickey(vendor_id, product_id, user_pin);
                }
                _            => {println!("no match!")},
            }
        } 
}

fn usb_export_publickey(vid: u16, pid: u16, u_pin: String) {
    let len = u_pin.len();
    let authinfo = DevAuthInfo {
        auth_key: String::from("1122334455667788"),
        auth_key_len: 16,
        app_name: String::from("osrapp"),
        app_name_len: 6,
        con_name: String::from("osr"),
        con_name_len: 3,
        ad_pin: String::from("123456"),
        ad_pin_len: 6,
        us_pin: u_pin,
        us_pin_len: len
    };

    let d = USBDevice::new(vid, pid);
    let mut public_key = Vec::with_capacity(256);
    let type_id = 0;
    d.export_public_key(&authinfo, &mut public_key, type_id);
    println!("{:02x?}", public_key); 
}

fn usb_check() {
    println!("printf, usb device info:");
    // USBDevice::libusb_info();

    let mut devinfo = DevInfo::default();
    USBDevice::skf_devinfo(&mut devinfo);
    println!("{:02x?}", devinfo);

    // usb check
    let authinfo = DevAuthInfo {
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
    };

    let d = USBDevice::new(0x2fd0, 0x1002);

    let mut random = Vec::with_capacity(32);
    d.skf_random(&mut random);
    println!("random: {:02x?}", random);

    let mut signdata = Vec::with_capacity(64);
    d.skf_sign(&authinfo, &random, &mut signdata);
    println!("signdata: {:02x?}", signdata);

    let mut public_key = Vec::with_capacity(256);
    let type_id = 0;
    d.export_public_key(&authinfo, &mut public_key, type_id);
    println!("signdata: {:02x?}", public_key);
}

