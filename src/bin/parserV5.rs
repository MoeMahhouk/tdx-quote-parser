use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use uuid::Uuid;
use std::env;
use std::fs::File;
use std::io::Read;
use hex;

#[derive(Debug)]
enum TEEType {
    SGX = 0x00000000,
    TDX = 0x00000081,
}

#[derive(Debug)]
struct QuoteHeader {
    version: u16,
    attestation_key_type: u16,
    tee_type: TEEType,
    reserved1: [u8; 2],
    reserved2: [u8; 2],
    qe_vendor_id: Uuid,
    user_data: [u8; 20],
}

#[derive(Debug)]
struct TDQuoteBody {
    tee_tcb_svn: [u8; 16],
    mrseam: [u8; 48],
    mrsignerseam: [u8; 48],
    seamattributes: [u8; 8],
    tdattributes: [u8; 8],
    xfam: [u8; 8],
    mrtd: [u8; 48],
    mrconfigid: [u8; 48],
    mrowner: [u8; 48],
    mrownerconfig: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    reportdata: [u8; 64],
    tee_tcb_svn_2: [u8; 16],
    mrservicetd: [u8; 48],
}

#[derive(Debug)]
struct QuoteBody {
    td_quote_body_type: u16,
    size: u32,
    td_quote_body: TDQuoteBody,
}

#[derive(Debug)]
struct Quote {
    header: QuoteHeader,
    body: QuoteBody,
}

fn parse_td_quote_body(cursor: &mut Cursor<&[u8]>) -> TDQuoteBody {
    TDQuoteBody {
        tee_tcb_svn: {
            let mut buf = [0; 16];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrseam: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrsignerseam: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        seamattributes: {
            let mut buf = [0; 8];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        tdattributes: {
            let mut buf = [0; 8];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        xfam: {
            let mut buf = [0; 8];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrtd: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrconfigid: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrowner: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrownerconfig: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        rtmr0: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        rtmr1: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        rtmr2: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        rtmr3: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        reportdata: {
            let mut buf = [0; 64];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        tee_tcb_svn_2: {
            let mut buf = [0; 16];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        mrservicetd: {
            let mut buf = [0; 48];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
    }
}

fn parse_quote(data: &[u8]) -> Quote {
    let mut cursor = Cursor::new(data);

    let header = QuoteHeader {
        version: cursor.read_u16::<LittleEndian>().unwrap(),
        attestation_key_type: cursor.read_u16::<LittleEndian>().unwrap(),
        tee_type: match cursor.read_u32::<LittleEndian>().unwrap() {
            0x00000000 => TEEType::SGX,
            0x00000081 => TEEType::TDX,
            _ => panic!("Invalid TEE type"),
        },
        reserved1: {
            let mut buf = [0; 2];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        reserved2: {
            let mut buf = [0; 2];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
        qe_vendor_id: {
            let mut buf = [0; 16];
            cursor.read_exact(&mut buf).unwrap();
            Uuid::from_bytes(buf)
        },
        user_data: {
            let mut buf = [0; 20];
            cursor.read_exact(&mut buf).unwrap();
            buf
        },
    };

    let body = QuoteBody {
        td_quote_body_type: cursor.read_u16::<LittleEndian>().unwrap(),
        size: cursor.read_u32::<LittleEndian>().unwrap(),
        td_quote_body: parse_td_quote_body(&mut cursor),
    };

    Quote { header, body }
}

fn extract_tdattributes_info(tdattributes: [u8; 8]) -> String {
    let tud = tdattributes[0];
    let sec = u32::from_le_bytes([0, tdattributes[1], tdattributes[2], tdattributes[3]]);
    let other = u64::from_le_bytes([0, 0, 0, 0, tdattributes[4], tdattributes[5], tdattributes[6], tdattributes[7]]);

    // Extract and format TUD flags
    let debug = if tud & 0b00000001 != 0 { "True" } else { "False" };
    let tud_reserved = (tud >> 1) & 0b01111111; // Extract reserved bits
    let tud_flags = format!("TUD:\n\t   DEBUG: {}\n\t   RESERVED: {}", debug, tud_reserved);

    // Extract and format SEC flags
    let sec_reserved = (sec >> 8) & 0b00001111_11111111_11111111; // Extract reserved bits
    let sept_ve_disable = (sec >> 27) & 0b00000001;
    let pks = (sec >> 30) & 0b00000001;
    let kl = (sec >> 31) & 0b00000001;
    let sec_flags = format!("\tSEC:\n\t  RESERVED: {}\n\t  SEPT_VE_DISABLE: {}\n\t  PKS: {}\n\t  KL: {}", sec_reserved, sept_ve_disable, pks, kl);

    // Extract and format OTHER flags
    let other_reserved = (other >> 32) & 0b01111111_11111111_11111111_11111111; // Extract reserved bits
    let perfmon = (other >> 63) & 0b00000001;
    let other_flags = format!("\tOTHER:\n\t  RESERVED: {}\n\t  PERFMON: {}", other_reserved, perfmon);

    format!("{}\n{}\n{}", tud_flags, sec_flags, other_flags)
}

fn main() {
    // Get the file path from the command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ./binary <file_path>");
        return;
    }
    let file_path = &args[1];

    // Read the file contents
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(err) => {
            println!("Error opening file: {}", err);
            return;
        }
    };
    let mut file_contents = Vec::new();
    if let Err(err) = file.read_to_end(&mut file_contents) {
        println!("Error reading file: {}", err);
        return;
    }

    // Parse the quote
    let quote = parse_quote(&file_contents);

    // Print the parsed data
    println!("Quote Header:");
    println!("  Version: {}", quote.header.version);
    println!("  Attestation Key Type: {}", quote.header.attestation_key_type);
    println!("  TEE Type: {:?}", quote.header.tee_type);
    println!("  Reserved 1: {}", hex::encode(&quote.header.reserved1));
    println!("  Reserved 2: {}", hex::encode(&quote.header.reserved2));
    println!("  QE Vendor ID: {}", quote.header.qe_vendor_id);
    println!("  User Data: {}", hex::encode(&quote.header.user_data));
    

    println!("Quote Body:");
    println!("  TD Quote Body Type: {}", quote.body.td_quote_body_type);
    println!("  Size: {}", quote.body.size);
    println!("  TEE TCB SVN: {}", hex::encode(&quote.body.td_quote_body.tee_tcb_svn));
    println!("  MRSEAM: {}", hex::encode(&quote.body.td_quote_body.mrseam));
    println!("  MRSIGNERSEAM: {}", hex::encode(&quote.body.td_quote_body.mrsignerseam));
    println!("  Seam Attributes: {}", hex::encode(&quote.body.td_quote_body.seamattributes));
    println!("  TD Attributes: {}", hex::encode(&quote.body.td_quote_body.tdattributes));
    println!("  \t{}", extract_tdattributes_info(quote.body.td_quote_body.tdattributes));
    println!("  XFAM: {}", hex::encode(&quote.body.td_quote_body.xfam));
    println!("  MRTD: {}", hex::encode(&quote.body.td_quote_body.mrtd));
    println!("  MRCONFIGID: {}", hex::encode(&quote.body.td_quote_body.mrconfigid));
    println!("  MROWNER: {}", hex::encode(&quote.body.td_quote_body.mrowner));
    println!("  MROWNERCONFIG: {}", hex::encode(&quote.body.td_quote_body.mrownerconfig));
    println!("  RTMR0: {}", hex::encode(&quote.body.td_quote_body.rtmr0));
    println!("  RTMR1: {}", hex::encode(&quote.body.td_quote_body.rtmr1));
    println!("  RTMR2: {}", hex::encode(&quote.body.td_quote_body.rtmr2));
    println!("  RTMR3: {}", hex::encode(&quote.body.td_quote_body.rtmr3));
    println!("  Report Data: {}", hex::encode(&quote.body.td_quote_body.reportdata));
    println!("  TEE TCB SVN 2: {}", hex::encode(&quote.body.td_quote_body.tee_tcb_svn_2));
    println!("  MRSERVICETD: {}", hex::encode(&quote.body.td_quote_body.mrservicetd));
}
