/*
FaF is a high performance DNS over TLS proxy
Copyright (C) 2022  James Bates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

lazy_static::lazy_static! {
   static ref REQWEST_AGENT: reqwest::Client = {
      reqwest::ClientBuilder::new().min_tls_version(reqwest::tls::Version::TLS_1_2).build().unwrap()
   };
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlocklistFile {
   pub file_path: std::path::PathBuf,
   pub last_modified: u64,
   pub blocked_domains: std::collections::HashSet<String>,
}

/*
  * Iterate over the BLOCKLISTS urls, and use reqwest to issue an HTTP HEAD requests (in parallel using Tokio spawn).
  * Parse the url and extract the filename, ignoring the rest of the path and removing the extension.
  * Check the data directory to see if the file exists, where the filename is the last segment from the URL.
  * If the file exists, deserialize and decompress the file into a BlockListFile.
  * If the file doesn't exist or the Last-Modified date from the header doesn't match the last_modified date in the BlockListFile,
  fetch the file using reqwest and parse the resonse body into a BlockListFile.
  * Serialize and compress the BlocklistFile and write it to the data directory.
  * Return the BlocklistFile from the original Tokio Task and collect it into a Vec<BlockListFile> and return them.
*/
#[inline]
pub async fn get_blocklists() -> Vec<BlocklistFile> {
   let mut blocklist_files: Vec<BlocklistFile> = Vec::with_capacity(crate::statics::BLOCKLISTS.len() + 1);

   {
      // Add manual blocklist from statics
      let manual_blocklist = BlocklistFile {
         file_path: std::path::PathBuf::from("manual_blocklist.bin"),
         last_modified: 0,
         blocked_domains: crate::statics::MANUAL_DOMAIN_BLOCKLIST.iter().map(|x| x.to_string()).collect(),
      };

      blocklist_files.push(manual_blocklist);
   }

  
   let mut tasks = Vec::with_capacity(crate::statics::BLOCKLISTS.len());
   for url in crate::statics::BLOCKLISTS.iter() {
      let task = tokio::spawn(async move {
         let mut file_path = crate::statics::ARGS.data_directory.clone().unwrap_or_else(std::env::temp_dir);
         file_path.push("faf-blocklists");
         std::fs::create_dir_all(&file_path).unwrap();
         let parsed_url = reqwest::Url::parse(url).unwrap();
         file_path.push(parsed_url.path_segments().unwrap().last().unwrap());
         file_path.set_extension("bin");

         let existing_blocklist_file: Option<BlocklistFile> = read_from_file_bincode::<BlocklistFile>(&file_path);

         let mut headers = reqwest::header::HeaderMap::new();
         headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(
               "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            ),
         );
         headers.insert(reqwest::header::ACCEPT, reqwest::header::HeaderValue::from_static("text/plain"));
         headers.insert(reqwest::header::ACCEPT_ENCODING, reqwest::header::HeaderValue::from_static("deflate"));
         headers.insert(reqwest::header::ACCEPT_LANGUAGE, reqwest::header::HeaderValue::from_static("en-US,en;q=0.9"));
         headers.insert(reqwest::header::CONNECTION, reqwest::header::HeaderValue::from_static("keep-alive"));
         headers.insert(reqwest::header::CACHE_CONTROL, reqwest::header::HeaderValue::from_static("no-cache"));
         headers.insert(reqwest::header::PRAGMA, reqwest::header::HeaderValue::from_static("no-cache"));

         let response = REQWEST_AGENT.head(*url).headers(headers.clone()).send().await.unwrap();
         let response_last_modified_str = response.headers().get(reqwest::header::LAST_MODIFIED).unwrap().to_str().unwrap();
         let response_last_modified_unix_timestamp =
            chrono::DateTime::parse_from_rfc2822(response_last_modified_str).unwrap().timestamp() as u64;

         let have_file_but_need_to_update = existing_blocklist_file.is_some()
            && existing_blocklist_file.as_ref().unwrap().last_modified != response_last_modified_unix_timestamp;
         let dont_have_file = existing_blocklist_file.is_none();

         if have_file_but_need_to_update || dont_have_file {
            println!("Downloading blocklist: {} -> {:?}", url, file_path);
            let response = REQWEST_AGENT.get(*url).headers(headers).send().await.unwrap();
            let content_encoding_maybe = response
               .headers()
               .get(reqwest::header::CONTENT_ENCODING)
               .map(|val| val.to_str().expect("Invalid encoding header").to_string());

            let response_str = response.text().await.unwrap();
            let response_bytes = response_str.as_bytes();

            let domains: Vec<String> = match content_encoding_maybe.as_deref() {
               Some("deflate") => {
                  use std::io::BufRead;
                  let deflate_decoder = flate2::read::DeflateDecoder::new(response_bytes);
                  let reader = std::io::BufReader::new(deflate_decoder);
                  reader.lines().map(|x| x.unwrap()).filter(|x| !x.is_empty() && !x.starts_with('#')).map(|x| x.to_string()).collect()
                  //  for line in reader.lines() {
                  //      let line_text = line.unwrap();
                  //      // process the uncompressed line here
                  //      println!("compressed line {}", line_text);
                  //  }
               }
               _ => {
                  use std::io::BufRead;
                  let reader = std::io::BufReader::new(response_bytes);
                  reader.lines().map(|x| x.unwrap()).filter(|x| !x.is_empty() && !x.starts_with('#')).map(|x| x.to_string()).collect()
                  //   for line in reader.lines() {
                  //       let line_text = line.unwrap();
                  //       // process the uncompressed line here
                  //       println!("uncompressed line {}", line_text);
                  //   }
               }
            };

            let mut blocklist_file = BlocklistFile {
               file_path: file_path.clone(),
               last_modified: response_last_modified_unix_timestamp,
               blocked_domains: std::collections::HashSet::with_capacity(domains.len()),
            };

            for line in domains {
               if line.starts_with('#') {
                  continue;
               }

               blocklist_file.blocked_domains.insert(line.to_owned());
            }

            write_to_file_bincode(&blocklist_file, &file_path).unwrap();
            blocklist_file
         } else {
            existing_blocklist_file.unwrap()
         }
      });

      tasks.push(task);
   }

   for task in tasks {
      let blocklist_file = task.await.unwrap();
      blocklist_files.push(blocklist_file);
   }

   blocklist_files
}

#[inline(always)]
fn write_to_file_bincode<T>(data: &T, absolute_path: &std::path::PathBuf) -> Option<()>
where
   T: serde::Serialize,
{
   use std::io::Write;

   let serialized_and_compressed_bytes = serialize_then_compress(data)?;
   let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(absolute_path).ok()?;
   let mut writer = std::io::BufWriter::new(f);
   writer.write_all(serialized_and_compressed_bytes.as_slice()).ok()?;
   writer.flush().ok()?;

   Some(())
}

#[inline(always)]
fn read_from_file_bincode<T>(absolute_path: &std::path::PathBuf) -> Option<T>
where
   T: serde::de::DeserializeOwned,
   T: std::fmt::Debug,
{
   use std::io::Read;

   let mut f = std::fs::File::open(absolute_path).ok()?;
   let file_len = f.metadata().ok()?.len();
   let mut bytes = Vec::with_capacity(file_len as usize + 1);
   f.read_to_end(&mut bytes).ok()?;
   decompress_then_deserialize(bytes.as_mut_slice())
}

#[inline(always)]
fn serialize_then_compress<T>(serializable: &T) -> Option<Vec<u8>>
where
   T: serde::Serialize,
{
   let bincode_bytes = bincode::serialize::<T>(serializable).ok()?;
   let compressed_bytes = compress_zlib(&bincode_bytes);
   Some(compressed_bytes)
}

#[inline(always)]
fn decompress_then_deserialize<T>(deserializable: &[u8]) -> Option<T>
where
   T: serde::de::DeserializeOwned,
{
   let mut decompressed_bytes = Vec::<u8>::new();
   decompress_zlib(deserializable, &mut decompressed_bytes);
   let deserialized_bytes = bincode::deserialize::<T>(&decompressed_bytes).ok()?;
   Some(deserialized_bytes)
}

#[inline(always)]
fn decompress_zlib(bytes: &[u8], buf_to_fill: &mut Vec<u8>) {
   use std::io::Read;

   let mut decompressor = flate2::read::ZlibDecoder::new(bytes);
   decompressor.read_to_end(buf_to_fill).unwrap();
}

#[inline(always)]
fn compress_zlib(bytes: &[u8]) -> Vec<u8> {
   use std::io::Write;

   let mut compressor = flate2::write::ZlibEncoder::new(Vec::with_capacity(bytes.len()), flate2::Compression::fast());
   compressor.write_all(bytes).unwrap();

   compressor.finish().unwrap()
}
