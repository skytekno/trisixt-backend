//! Hardware marketing names, preserving raw values until a validated refresh.
use crate::{error::AppError, state::AppState};
use std::{collections::HashMap, time::Duration};

pub fn apple_name(model: &str) -> &str {
    match model {
        "iPod5,1" => "iPod touch (5th generation)",
        "iPod7,1" => "iPod touch (6th generation)",
        "iPod9,1" => "iPod touch (7th generation)",
        "iPhone3,1" => "iPhone 4",
        "iPhone3,2" => "iPhone 4",
        "iPhone3,3" => "iPhone 4",
        "iPhone4,1" => "iPhone 4s",
        "iPhone5,1" => "iPhone 5",
        "iPhone5,2" => "iPhone 5",
        "iPhone5,3" => "iPhone 5c",
        "iPhone5,4" => "iPhone 5c",
        "iPhone6,1" => "iPhone 5s",
        "iPhone6,2" => "iPhone 5s",
        "iPhone7,2" => "iPhone 6",
        "iPhone7,1" => "iPhone 6 Plus",
        "iPhone8,1" => "iPhone 6s",
        "iPhone8,2" => "iPhone 6s Plus",
        "iPhone8,4" => "iPhone SE",
        "iPhone9,1" => "iPhone 7",
        "iPhone9,3" => "iPhone 7",
        "iPhone9,2" => "iPhone 7 Plus",
        "iPhone9,4" => "iPhone 7 Plus",
        "iPhone10,1" => "iPhone 8",
        "iPhone10,4" => "iPhone 8",
        "iPhone10,2" => "iPhone 8 Plus",
        "iPhone10,5" => "iPhone 8 Plus",
        "iPhone10,3" => "iPhone X",
        "iPhone10,6" => "iPhone X",
        "iPhone11,2" => "iPhone XS",
        "iPhone11,4" => "iPhone XS Max",
        "iPhone11,6" => "iPhone XS Max",
        "iPhone11,8" => "iPhone XR",
        "iPhone12,1" => "iPhone 11",
        "iPhone12,3" => "iPhone 11 Pro",
        "iPhone12,5" => "iPhone 11 Pro Max",
        "iPhone12,8" => "iPhone SE (2nd generation)",
        "iPhone13,1" => "iPhone 12 mini",
        "iPhone13,2" => "iPhone 12",
        "iPhone13,3" => "iPhone 12 Pro",
        "iPhone13,4" => "iPhone 12 Pro Max",
        "iPhone14,4" => "iPhone 13 mini",
        "iPhone14,5" => "iPhone 13",
        "iPhone14,2" => "iPhone 13 Pro",
        "iPhone14,3" => "iPhone 13 Pro Max",
        "iPhone14,6" => "iPhone SE (3rd generation)",
        "iPhone14,7" => "iPhone 14",
        "iPhone14,8" => "iPhone 14 Plus",
        "iPhone15,2" => "iPhone 14 Pro",
        "iPhone15,3" => "iPhone 14 Pro Max",
        "iPhone15,4" => "iPhone 15",
        "iPhone15,5" => "iPhone 15 Plus",
        "iPhone16,1" => "iPhone 15 Pro",
        "iPhone16,2" => "iPhone 15 Pro Max",
        "iPhone17,1" => "iPhone 16 Pro",
        "iPhone17,2" => "iPhone 16 Pro Max",
        "iPhone17,3" => "iPhone 16",
        "iPhone17,4" => "iPhone 16 Plus",
        "iPhone17,5" => "iPhone 16e",
        "iPhone18,1" => "iPhone 17 Pro",
        "iPhone18,2" => "iPhone 17 Pro Max",
        "iPhone18,3" => "iPhone 17",
        "iPhone18,4" => "iPhone Air",
        "iPad2,1" => "iPad 2",
        "iPad2,2" => "iPad 2",
        "iPad2,3" => "iPad 2",
        "iPad2,4" => "iPad 2",
        "iPad3,1" => "iPad (3rd generation)",
        "iPad3,2" => "iPad (3rd generation)",
        "iPad3,3" => "iPad (3rd generation)",
        "iPad3,4" => "iPad (4th generation)",
        "iPad3,5" => "iPad (4th generation)",
        "iPad3,6" => "iPad (4th generation)",
        "iPad6,11" => "iPad (5th generation)",
        "iPad6,12" => "iPad (5th generation)",
        "iPad7,5" => "iPad (6th generation)",
        "iPad7,6" => "iPad (6th generation)",
        "iPad7,11" => "iPad (7th generation)",
        "iPad7,12" => "iPad (7th generation)",
        "iPad11,6" => "iPad (8th generation)",
        "iPad11,7" => "iPad (8th generation)",
        "iPad12,1" => "iPad (9th generation)",
        "iPad12,2" => "iPad (9th generation)",
        "iPad13,18" => "iPad (10th generation)",
        "iPad13,19" => "iPad (10th generation)",
        "iPad15,7" => "iPad (A16)",
        "iPad15,8" => "iPad (A16)",
        "iPad4,1" => "iPad Air",
        "iPad4,2" => "iPad Air",
        "iPad4,3" => "iPad Air",
        "iPad5,3" => "iPad Air 2",
        "iPad5,4" => "iPad Air 2",
        "iPad11,3" => "iPad Air (3rd generation)",
        "iPad11,4" => "iPad Air (3rd generation)",
        "iPad13,1" => "iPad Air (4th generation)",
        "iPad13,2" => "iPad Air (4th generation)",
        "iPad13,16" => "iPad Air (5th generation)",
        "iPad13,17" => "iPad Air (5th generation)",
        "iPad14,8" => "iPad Air 11-inch (M2)",
        "iPad14,9" => "iPad Air 11-inch (M2)",
        "iPad14,10" => "iPad Air 13-inch (M2)",
        "iPad14,11" => "iPad Air 13-inch (M2)",
        "iPad15,3" => "iPad Air 11-inch (M3)",
        "iPad15,4" => "iPad Air 11-inch (M3)",
        "iPad15,5" => "iPad Air 13-inch (M3)",
        "iPad15,6" => "iPad Air 13-inch (M3)",
        "iPad2,5" => "iPad mini",
        "iPad2,6" => "iPad mini",
        "iPad2,7" => "iPad mini",
        "iPad4,4" => "iPad mini 2",
        "iPad4,5" => "iPad mini 2",
        "iPad4,6" => "iPad mini 2",
        "iPad4,7" => "iPad mini 3",
        "iPad4,8" => "iPad mini 3",
        "iPad4,9" => "iPad mini 3",
        "iPad5,1" => "iPad mini 4",
        "iPad5,2" => "iPad mini 4",
        "iPad11,1" => "iPad mini (5th generation)",
        "iPad11,2" => "iPad mini (5th generation)",
        "iPad14,1" => "iPad mini (6th generation)",
        "iPad14,2" => "iPad mini (6th generation)",
        "iPad16,1" => "iPad mini (A17 Pro)",
        "iPad16,2" => "iPad mini (A17 Pro)",
        "iPad6,3" => "iPad Pro (9.7-inch)",
        "iPad6,4" => "iPad Pro (9.7-inch)",
        "iPad7,3" => "iPad Pro (10.5-inch)",
        "iPad7,4" => "iPad Pro (10.5-inch)",
        "iPad8,1" => "iPad Pro (11-inch) (1st generation)",
        "iPad8,2" => "iPad Pro (11-inch) (1st generation)",
        "iPad8,3" => "iPad Pro (11-inch) (1st generation)",
        "iPad8,4" => "iPad Pro (11-inch) (1st generation)",
        "iPad8,9" => "iPad Pro (11-inch) (2nd generation)",
        "iPad8,10" => "iPad Pro (11-inch) (2nd generation)",
        "iPad13,4" => "iPad Pro (11-inch) (3rd generation)",
        "iPad13,5" => "iPad Pro (11-inch) (3rd generation)",
        "iPad13,6" => "iPad Pro (11-inch) (3rd generation)",
        "iPad13,7" => "iPad Pro (11-inch) (3rd generation)",
        "iPad14,3" => "iPad Pro (11-inch) (4th generation)",
        "iPad14,4" => "iPad Pro (11-inch) (4th generation)",
        "iPad6,7" => "iPad Pro (12.9-inch) (1st generation)",
        "iPad6,8" => "iPad Pro (12.9-inch) (1st generation)",
        "iPad7,1" => "iPad Pro (12.9-inch) (2nd generation)",
        "iPad7,2" => "iPad Pro (12.9-inch) (2nd generation)",
        "iPad8,5" => "iPad Pro (12.9-inch) (3rd generation)",
        "iPad8,6" => "iPad Pro (12.9-inch) (3rd generation)",
        "iPad8,7" => "iPad Pro (12.9-inch) (3rd generation)",
        "iPad8,8" => "iPad Pro (12.9-inch) (3rd generation)",
        "iPad8,11" => "iPad Pro (12.9-inch) (4th generation)",
        "iPad8,12" => "iPad Pro (12.9-inch) (4th generation)",
        "iPad13,8" => "iPad Pro (12.9-inch) (5th generation)",
        "iPad13,9" => "iPad Pro (12.9-inch) (5th generation)",
        "iPad13,10" => "iPad Pro (12.9-inch) (5th generation)",
        "iPad13,11" => "iPad Pro (12.9-inch) (5th generation)",
        "iPad14,5" => "iPad Pro (12.9-inch) (6th generation)",
        "iPad14,6" => "iPad Pro (12.9-inch) (6th generation)",
        "iPad16,3" => "iPad Pro 11-inch (M4)",
        "iPad16,4" => "iPad Pro 11-inch (M4)",
        "iPad16,5" => "iPad Pro 13-inch (M4)",
        "iPad16,6" => "iPad Pro 13-inch (M4)",
        _ => model,
    }
}
const GOOGLE_CSV: &str = "https://storage.googleapis.com/play_public/supported_devices.csv";
const MAX_CSV_BYTES: usize = 32 * 1024 * 1024;
/// Strict validation happens before the currently serving table is touched.
pub fn parse_android_csv(bytes: &[u8]) -> Result<HashMap<String, String>, AppError> {
    if bytes.is_empty() || bytes.len() > MAX_CSV_BYTES {
        return Err(AppError::Upstream);
    }
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.get(1) == Some(&0) {
        if !bytes.len().is_multiple_of(2) {
            return Err(AppError::Upstream);
        }
        let words = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&words)
            .map_err(|_| AppError::Upstream)?
            .trim_start_matches('\u{feff}')
            .to_owned()
    } else {
        std::str::from_utf8(bytes)
            .map_err(|_| AppError::Upstream)?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    let mut csv = csv::Reader::from_reader(text.as_bytes());
    if csv
        .headers()
        .map_err(|_| AppError::Upstream)?
        .iter()
        .collect::<Vec<_>>()
        != ["Retail Branding", "Marketing Name", "Device", "Model"]
    {
        return Err(AppError::Upstream);
    }
    let mut map = HashMap::new();
    let mut count = 0;
    for row in csv.records() {
        count += 1;
        if count > 500_000 {
            return Err(AppError::Upstream);
        }
        let row = row.map_err(|_| AppError::Upstream)?;
        let brand = row[0].trim();
        let marketing = row[1].trim();
        let model = row[3].trim();
        if model.is_empty() || marketing.is_empty() {
            continue;
        }
        let name = if brand.is_empty() {
            marketing.to_owned()
        } else {
            format!("{brand} {marketing}")
        };
        if model.len() > 255 || name.len() > 512 || name == model {
            continue;
        }
        map.entry(model.to_owned()).or_insert(name);
    }
    if count < 40_000 || map.len() < 20_000 {
        return Err(AppError::Upstream);
    }
    Ok(map)
}
pub async fn humanize(st: &AppState, platform: &str, model: &str) -> Result<String, AppError> {
    if model.is_empty() {
        return Ok(String::new());
    }
    if platform == "ios" {
        return Ok(apple_name(model).into());
    }
    if platform != "android" {
        return Ok(model.into());
    }
    if let Some(name) =
        sqlx::query_scalar::<_, String>("SELECT name FROM android_hardware_models WHERE model=$1")
            .bind(model)
            .fetch_optional(&st.pg)
            .await?
    {
        return Ok(name);
    }
    sqlx::query("INSERT INTO hardware_refresh_state(singleton)VALUES(true)ON CONFLICT DO NOTHING")
        .execute(&st.pg)
        .await?;
    Ok(model.into())
}
pub async fn install_android(st: &AppState, bytes: &[u8]) -> Result<usize, AppError> {
    let map = parse_android_csv(bytes)?;
    let count = map.len();
    let (models, names): (Vec<_>, Vec<_>) = map.into_iter().unzip();
    let mut tx = st.pg.begin().await?;
    sqlx::query("LOCK TABLE android_hardware_models IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM android_hardware_models")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO android_hardware_models(model,name) SELECT * FROM unnest($1::text[],$2::text[])").bind(models).bind(names).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO hardware_refresh_state(singleton,available_at,updated_at)VALUES(true,now()+interval '7 days',now())ON CONFLICT(singleton)DO UPDATE SET available_at=excluded.available_at,updated_at=now(),attempts=0,last_error=NULL").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(count)
}
pub async fn tick(st: &AppState) -> Result<usize, AppError> {
    let claimed:bool=sqlx::query_scalar("UPDATE hardware_refresh_state SET available_at=now()+interval '10 minutes' WHERE singleton AND available_at<=now()RETURNING true").fetch_optional(&st.pg).await?.unwrap_or(false);
    if !claimed {
        return Ok(0);
    }
    let refresh = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Internal)?;
        let mut response = client
            .get(GOOGLE_CSV)
            .send()
            .await
            .map_err(|_| AppError::Upstream)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_CSV_BYTES as u64)
        {
            return Err(AppError::Upstream);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Upstream)? {
            if bytes.len() + chunk.len() > MAX_CSV_BYTES {
                return Err(AppError::Upstream);
            }
            bytes.extend_from_slice(&chunk)
        }
        install_android(st, &bytes).await
    }
    .await;
    if refresh.is_err() {
        sqlx::query("UPDATE hardware_refresh_state SET attempts=attempts+1,last_error='validated device table refresh failed'WHERE singleton").execute(&st.pg).await?;
    }
    refresh
}
