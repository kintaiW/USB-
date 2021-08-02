extern crate libusb;
use std::slice;
use std::str::FromStr;
use std::time::Duration;

struct UsbDevice<'a> {
    handle: libusb::DeviceHandle<'a>,
    language: libusb::Language,
    timeout: Duration
}

#[derive(Debug)]
struct Endpoint {
    config: u8,
    iface: u8,
    setting: u8,
    address: u8
}

pub fn libusb_info() {
    let version = libusb::version();

    println!("libusb v{}.{}.{}.{}{}", version.major(), version.minor(), version.micro(), version.nano(), version.rc().unwrap_or(""));

    let mut context = match libusb::Context::new() {
        Ok(c) => c,
        Err(e) => panic!("libusb::Context::new(): {}", e)
    };

    context.set_log_level(libusb::LogLevel::Debug);
    context.set_log_level(libusb::LogLevel::Info);
    context.set_log_level(libusb::LogLevel::Warning);
    context.set_log_level(libusb::LogLevel::Error);
    context.set_log_level(libusb::LogLevel::None);

    println!("has capability? {}", context.has_capability());
    println!("has hotplug? {}", context.has_hotplug());
    println!("has HID access? {}", context.has_hid_access());
    println!("supports detach kernel driver? {}", context.supports_detach_kernel_driver())
}

pub fn lsusb() -> libusb::Result<()> {
    let context = libusb::Context::new()?;

    for device in context.devices()?.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue
        };
        println!("Bus {:03} Device {:03} ID {:04x}:{:04x} {}", device.bus_number(), device.address(), device_desc.vendor_id(), device_desc.product_id(), get_speed(device.speed()));
        
     };
     Ok(())
}

pub fn list_devices() -> libusb::Result<()>{
    let timeout = Duration::from_secs(1);

    let context = libusb::Context::new()?;

    for device in context.devices()?.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue
        };

        let mut usb_device = {
            match device.open() {
                Ok(h) => {
                    match h.read_languages(timeout) {
                        Ok(l) => {
                            if l.len() > 0 {
                                Some(UsbDevice {
                                    handle: h,
                                    language: l[0],
                                    timeout: timeout
                                })
                            }
                            else {
                                None
                            }
                        },
                        Err(_) => None
                    }
                },
                Err(_) => None
            }
        };

        println!("Bus {:03} Device {:03} ID {:04x}:{:04x} {}", device.bus_number(), device.address(), device_desc.vendor_id(), device_desc.product_id(), get_speed(device.speed()));
        print_device(&device_desc, &mut usb_device);

        for n in 0..device_desc.num_configurations() {
            let config_desc = match device.config_descriptor(n) {
                Ok(c) => c,
                Err(_) => continue
            };

            print_config(&config_desc, &mut usb_device);

            for interface in config_desc.interfaces() {
                for interface_desc in interface.descriptors() {
                    print_interface(&interface_desc, &mut usb_device);

                    for endpoint_desc in interface_desc.endpoint_descriptors() {
                        print_endpoint(&endpoint_desc);
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_device(device_desc: &libusb::DeviceDescriptor, handle: &mut Option<UsbDevice>) {
    println!("Device Descriptor:");
    println!("  bcdUSB             {:2}.{}{}", device_desc.usb_version().major(), device_desc.usb_version().minor(), device_desc.usb_version().sub_minor());
    println!("  bDeviceClass        {:#04x}", device_desc.class_code());
    println!("  bDeviceSubClass     {:#04x}", device_desc.sub_class_code());
    println!("  bDeviceProtocol     {:#04x}", device_desc.protocol_code());
    println!("  bMaxPacketSize0      {:3}", device_desc.max_packet_size());
    println!("  idVendor          {:#06x}", device_desc.vendor_id());
    println!("  idProduct         {:#06x}", device_desc.product_id());
    println!("  bcdDevice          {:2}.{}{}", device_desc.device_version().major(), device_desc.device_version().minor(), device_desc.device_version().sub_minor());
    println!("  iManufacturer        {:3} {}",
             device_desc.manufacturer_string_index().unwrap_or(0),
             handle.as_mut().map_or(String::new(), |h| h.handle.read_manufacturer_string(h.language, device_desc, h.timeout).unwrap_or(String::new())));
    println!("  iProduct             {:3} {}",
             device_desc.product_string_index().unwrap_or(0),
             handle.as_mut().map_or(String::new(), |h| h.handle.read_product_string(h.language, device_desc, h.timeout).unwrap_or(String::new())));
    println!("  iSerialNumber        {:3} {}",
             device_desc.serial_number_string_index().unwrap_or(0),
             handle.as_mut().map_or(String::new(), |h| h.handle.read_serial_number_string(h.language, device_desc, h.timeout).unwrap_or(String::new())));
    println!("  bNumConfigurations   {:3}", device_desc.num_configurations());
}

fn print_config(config_desc: &libusb::ConfigDescriptor, handle: &mut Option<UsbDevice>) {
    println!("  Config Descriptor:");
    println!("    bNumInterfaces       {:3}", config_desc.num_interfaces());
    println!("    bConfigurationValue  {:3}", config_desc.number());
    println!("    iConfiguration       {:3} {}",
             config_desc.description_string_index().unwrap_or(0),
             handle.as_mut().map_or(String::new(), |h| h.handle.read_configuration_string(h.language, config_desc, h.timeout).unwrap_or(String::new())));
    println!("    bmAttributes:");
    println!("      Self Powered     {:>5}", config_desc.self_powered());
    println!("      Remote Wakeup    {:>5}", config_desc.remote_wakeup());
    println!("    bMaxPower           {:4}mW", config_desc.max_power());
}

fn print_interface(interface_desc: &libusb::InterfaceDescriptor, handle: &mut Option<UsbDevice>) {
    println!("    Interface Descriptor:");
    println!("      bInterfaceNumber     {:3}", interface_desc.interface_number());
    println!("      bAlternateSetting    {:3}", interface_desc.setting_number());
    println!("      bNumEndpoints        {:3}", interface_desc.num_endpoints());
    println!("      bInterfaceClass     {:#04x}", interface_desc.class_code());
    println!("      bInterfaceSubClass  {:#04x}", interface_desc.sub_class_code());
    println!("      bInterfaceProtocol  {:#04x}", interface_desc.protocol_code());
    println!("      iInterface           {:3} {}",
             interface_desc.description_string_index().unwrap_or(0),
             handle.as_mut().map_or(String::new(), |h| h.handle.read_interface_string(h.language, interface_desc, h.timeout).unwrap_or(String::new())));
}

fn print_endpoint(endpoint_desc: &libusb::EndpointDescriptor) {
    println!("      Endpoint Descriptor:");
    println!("        bEndpointAddress    {:#04x} EP {} {:?}", endpoint_desc.address(), endpoint_desc.number(), endpoint_desc.direction());
    println!("        bmAttributes:");
    println!("          Transfer Type          {:?}", endpoint_desc.transfer_type());
    println!("          Synch Type             {:?}", endpoint_desc.sync_type());
    println!("          Usage Type             {:?}", endpoint_desc.usage_type());
    println!("        wMaxPacketSize    {:#06x}", endpoint_desc.max_packet_size());
    println!("        bInterval            {:3}", endpoint_desc.interval());
}

fn get_speed(speed: libusb::Speed) -> &'static str {
    match speed {
        libusb::Speed::Super   => "5000 Mbps",
        libusb::Speed::High    => " 480 Mbps",
        libusb::Speed::Full    => "  12 Mbps",
        libusb::Speed::Low     => " 1.5 Mbps",
        libusb::Speed::Unknown => "(unknown)"
    }
}


pub fn read_devices(vid: u16, pid: u16) {
    // let vid: u16 = FromStr::from_str(vid).unwrap();
    // let pid: u16 = FromStr::from_str(pid).unwrap();

    match libusb::Context::new() {
        Ok(mut context) => {
            match open_device(&mut context, vid, pid) {
                Some((mut device, device_desc, mut handle)) => read_device(&mut device, &device_desc, &mut handle).unwrap(),
                None => println!("could not find device {:04x}:{:04x}", vid, pid)
            }
        },
        Err(e) => panic!("could not initialize libusb: {}", e)
    }
}

fn open_device(context: &mut libusb::Context, vid: u16, pid: u16) -> Option<(libusb::Device, libusb::DeviceDescriptor, libusb::DeviceHandle)> {
    let devices = match context.devices() {
        Ok(d) => d,
        Err(_) => return None
    };

    for device in devices.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue
        };

        if device_desc.vendor_id() == vid && device_desc.product_id() == pid {
            match device.open() {
                Ok(handle) => return Some((device, device_desc, handle)),
                Err(_) => continue
            }
        }
    }

    None
}

fn read_device(device: &mut libusb::Device, device_desc: &libusb::DeviceDescriptor, handle: &mut libusb::DeviceHandle) -> libusb::Result<()> {
    handle.reset()?;

    let timeout = Duration::from_secs(1);
    let languages = handle.read_languages(timeout)?;

    println!("Active configuration: {}", handle.active_configuration()?);
    println!("Languages: {:?}", languages);

    if languages.len() > 0 {
        let language = languages[0];

        println!("Manufacturer: {:?}", handle.read_manufacturer_string(language, device_desc, timeout).ok());
        println!("Product: {:?}", handle.read_product_string(language, device_desc, timeout).ok());
        println!("Serial Number: {:?}", handle.read_serial_number_string(language, device_desc, timeout).ok());
    }

    match find_readable_endpoint(device, device_desc, libusb::TransferType::Interrupt) {
        Some(endpoint) => read_endpoint(handle, endpoint, libusb::TransferType::Interrupt),
        None => println!("No readable interrupt endpoint")
    }

    match find_readable_endpoint(device, device_desc, libusb::TransferType::Bulk) {
        Some(endpoint) => read_endpoint(handle, endpoint, libusb::TransferType::Bulk),
        None => println!("No readable bulk endpoint")
    }

    Ok(())
}

fn find_readable_endpoint(device: &mut libusb::Device, device_desc: &libusb::DeviceDescriptor, transfer_type: libusb::TransferType) -> Option<Endpoint> {
    for n in 0..device_desc.num_configurations() {
        let config_desc = match device.config_descriptor(n) {
            Ok(c) => c,
            Err(_) => continue
        };

        for interface in config_desc.interfaces() {
            for interface_desc in interface.descriptors() {
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    if endpoint_desc.direction() == libusb::Direction::In && endpoint_desc.transfer_type() == transfer_type {
                        return Some(Endpoint {
                            config: config_desc.number(),
                            iface: interface_desc.interface_number(),
                            setting: interface_desc.setting_number(),
                            address: endpoint_desc.address()
                        });
                    }
                }
            }
        }
    }

    None
}

fn read_endpoint(handle: &mut libusb::DeviceHandle, endpoint: Endpoint, transfer_type: libusb::TransferType) {
    println!("Reading from endpoint: {:?}", endpoint);

    let has_kernel_driver = match handle.kernel_driver_active(endpoint.iface) {
        Ok(true) => {
            handle.detach_kernel_driver(endpoint.iface).ok();
            true
        },
        _ => false
    };

    println!(" - kernel driver? {}", has_kernel_driver);

    match configure_endpoint(handle, &endpoint) {
        Ok(_) => {
            let mut vec = Vec::<u8>::with_capacity(256);
            let mut buf = unsafe { slice::from_raw_parts_mut((&mut vec[..]).as_mut_ptr(), vec.capacity()) };

            let timeout = Duration::from_secs(1);

            match transfer_type {
                libusb::TransferType::Interrupt => {
                    match handle.read_interrupt(endpoint.address, buf, timeout) {
                        Ok(len) => {
                            unsafe { vec.set_len(len) };
                            println!(" - read: {:?}", vec);
                        },
                        Err(err) => println!("could not read from endpoint: {}", err)
                    }
                },
                libusb::TransferType::Bulk => {
                    match handle.read_bulk(endpoint.address, buf, timeout) {
                        Ok(len) => {
                            unsafe { vec.set_len(len) };
                            println!(" - read: {:?}", vec);
                        },
                        Err(err) => println!("could not read from endpoint: {}", err)
                    }
                },
                _ => ()
            }
        },
        Err(err) => println!("could not configure endpoint: {}", err)
    }

    if has_kernel_driver {
        handle.attach_kernel_driver(endpoint.iface).ok();
    }
}

fn configure_endpoint<'a>(handle: &'a mut libusb::DeviceHandle, endpoint: &Endpoint) -> libusb::Result<()> {
    handle.set_active_configuration(endpoint.config)?;
    handle.claim_interface(endpoint.iface)?;
    handle.set_alternate_setting(endpoint.iface, endpoint.setting)?;
    Ok(())
}