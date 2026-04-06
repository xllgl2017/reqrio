mod timeout;

use std::time::{SystemTime, UNIX_EPOCH};
pub use timeout::Timeout;
use std::fmt::{Display, Formatter};
use std::error::Error;

#[derive(Debug)]
pub enum TimeError {
    GetTimeNowError,
    InvalidYear,
    InvalidMonth,
    InvalidDay,
    InvalidHour,
    InvalidMinute,
    InvalidSecond,
    InvalidMills,
    InvalidWeekday,
    InvalidRfc1123,
    InvalidRfc3339,
    InvalidCommon,
    ReadTimeout,
    WriteTimeout,
    FlushTimeout,
    ShutdownTimeout,
}

impl Display for TimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for TimeError {}

#[derive(Debug)]
pub struct Time {
    year: u128,
    month: u128,
    day: u128,
    hour: u128,
    minute: u128,
    secs: u128,
    msec: u128,
    weekday: u128,
}

impl Time {
    const SECS_PER_DAY: u128 = 86_400_000;
    const WEEKDAY: [&'static str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTH: [&'static str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    pub fn now() -> Result<Time, TimeError> {
        let dt = SystemTime::now().duration_since(UNIX_EPOCH).or(Err(TimeError::GetTimeNowError))?;
        Ok(Time::from_msecs(dt.as_millis()))
    }

    pub fn now_utc8() -> Result<Time, TimeError> {
        let dt = SystemTime::now().duration_since(UNIX_EPOCH).or(Err(TimeError::GetTimeNowError))?;
        Ok(Time::from_msecs(dt.as_millis()))
    }

    pub fn now_secs() -> Result<u64, TimeError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH).or(Err(TimeError::GetTimeNowError))?.as_secs())
    }

    pub fn now_mills() -> Result<u128, TimeError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH).or(Err(TimeError::GetTimeNowError))?.as_millis())
    }

    pub fn now_nanos() -> Result<u128, TimeError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH).or(Err(TimeError::GetTimeNowError))?.as_nanos())
    }

    pub fn from_secs(secs: u64) -> Time {
        Time::from_msecs(secs as u128 * 1000)
    }

    pub fn from_msecs(msecs: u128) -> Time {
        // 处理时间（秒 -> 时分秒）
        let days = msecs.div_euclid(Time::SECS_PER_DAY);
        let rem = msecs.rem_euclid(Time::SECS_PER_DAY);


        let msecs = rem % 1000;
        let secs = (rem / 1000) % 60;
        let minute = (rem / 1000 / 60) % 60;
        let hour = (rem / 1000 / 60 / 60) % 24;

        let z = days + 719468;

        let era = z / 146097;

        let doe = z - era * 146097;                       // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let mut year = yoe + era * 400;

        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);      // [0, 365]
        let mp = (5 * doy + 2) / 153;                       // [0, 11]

        let day = doy - (153 * mp + 2) / 5 + 1;                 // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 };

        year += if month <= 2 { 1 } else { 0 };

        Time {
            year,
            month,
            day,
            hour,
            minute,
            secs,
            msec: msecs,
            weekday: days % 7,
        }
    }

    fn push_num(&self, buf: &mut String, mut n: u128, width: usize) {
        let start = buf.len();

        for _ in 0..width {
            buf.push('0');
        }

        let mut i = start + width;

        while n > 0 && i > start {
            i -= 1;
            unsafe {
                buf.as_mut_vec()[i] = b'0' + (n % 10) as u8;
            }
            n /= 10;
        }
    }

    pub fn rfc1123(&self) -> String {
        let mut res = String::with_capacity(32);
        res.push_str(Time::WEEKDAY[self.weekday as usize]);
        res.push_str(", ");
        self.push_num(&mut res, self.day, 2);
        res.push(' ');
        res.push_str(Time::MONTH[self.month as usize - 1]);
        res.push(' ');
        self.push_num(&mut res, self.year, 4);
        res.push(' ');
        self.push_num(&mut res, self.hour, 2);
        res.push(':');
        self.push_num(&mut res, self.minute, 2);
        res.push(':');
        self.push_num(&mut res, self.secs, 2);
        res.push_str(" GMT");
        res
    }

    pub fn rfc3339(&self) -> String {
        let mut res = String::with_capacity(32);
        self.push_num(&mut res, self.year, 4);
        res.push('-');
        self.push_num(&mut res, self.month, 2);
        res.push('-');
        self.push_num(&mut res, self.day, 2);
        res.push('T');
        self.push_num(&mut res, self.hour, 2);
        res.push(':');
        self.push_num(&mut res, self.minute, 2);
        res.push(':');
        self.push_num(&mut res, self.secs, 2);
        res.push('.');
        self.push_num(&mut res, self.msec, 3);
        res.push('Z');
        res
    }

    pub fn common(&self) -> String {
        let mut res = String::with_capacity(32);
        self.push_num(&mut res, self.year, 4);
        res.push('-');
        self.push_num(&mut res, self.month, 2);
        res.push('-');
        self.push_num(&mut res, self.day, 2);
        res.push(' ');
        self.push_num(&mut res, self.hour, 2);
        res.push(':');
        self.push_num(&mut res, self.minute, 2);
        res.push(':');
        self.push_num(&mut res, self.secs, 2);
        res
    }

    ///Sat, 04 Apr 2026 13:42:35 GMT
    pub fn from_rfc1123(s: impl AsRef<[u8]>) -> Result<Time, TimeError> {
        let rfc1123_bs = s.as_ref();
        if rfc1123_bs.len() < 29 {
            return Err(TimeError::InvalidRfc1123);
        }

        let weekday = match &rfc1123_bs[0..3] {
            b"Sun" => 3,
            b"Mon" => 4,
            b"Tue" => 5,
            b"Wed" => 6,
            b"Thu" => 0,
            b"Fri" => 1,
            b"Sat" => 2,
            _ => return Err(TimeError::InvalidWeekday),
        };
        if rfc1123_bs[3] != b',' || rfc1123_bs[4] != b' ' || rfc1123_bs[7] != b' ' || rfc1123_bs[11] != b' ' || rfc1123_bs[16] != b' ' {
            return Err(TimeError::InvalidRfc1123);
        }
        let day = Time::parse_2d(&rfc1123_bs[5..7]).ok_or(TimeError::InvalidDay)?;

        let month = match &rfc1123_bs[8..11] {
            b"Jan" => 1,
            b"Feb" => 2,
            b"Mar" => 3,
            b"Apr" => 4,
            b"May" => 5,
            b"Jun" => 6,
            b"Jul" => 7,
            b"Aug" => 8,
            b"Sep" => 9,
            b"Oct" => 10,
            b"Nov" => 11,
            b"Dec" => 12,
            _ => return Err(TimeError::InvalidMonth),
        };

        let year = Time::parse_4d(&rfc1123_bs[12..16]).ok_or(TimeError::InvalidYear)?;
        let hour = Time::parse_2d(&rfc1123_bs[17..19]).ok_or(TimeError::InvalidHour)?;
        if rfc1123_bs[19] != b':' || rfc1123_bs[22] != b':' || rfc1123_bs[25] != b' ' || &rfc1123_bs[26..29] != b"GMT" {
            return Err(TimeError::InvalidRfc1123);
        }
        let minute = Time::parse_2d(&rfc1123_bs[20..22]).ok_or(TimeError::InvalidMinute)?;
        let second = Time::parse_2d(&rfc1123_bs[23..25]).ok_or(TimeError::InvalidSecond)?;
        Ok(Time {
            year,
            month,
            day,
            hour,
            minute,
            secs: second,
            msec: 0,
            weekday,
        })
    }

    ///2026-03-26T10:02:19.911Z
    pub fn from_rfc3339(s: impl AsRef<[u8]>) -> Result<Time, TimeError> {
        let b = s.as_ref();
        let len = b.len();
        if len < 20 {
            return Err(TimeError::InvalidRfc3339);
        }
        if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return Err(TimeError::InvalidRfc3339);
        }
        let year = Time::parse_4d(&b[0..4]).ok_or(TimeError::InvalidYear)?;
        let month = Time::parse_2d(&b[5..7]).ok_or(TimeError::InvalidMonth)?;
        let day = Time::parse_2d(&b[8..10]).ok_or(TimeError::InvalidDay)?;
        let hour = Time::parse_2d(&b[11..13]).ok_or(TimeError::InvalidHour)?;
        let minute = Time::parse_2d(&b[14..16]).ok_or(TimeError::InvalidMinute)?;
        let second = Time::parse_2d(&b[17..19]).ok_or(TimeError::InvalidSecond)?;
        let days = Time::days(year, month, day);

        let mut i = 19;
        let mut msecs = 0;
        if i < len && b[i] == b'.' {
            i += 1;

            let mut val = 0u128;
            let mut digits = 0;

            while i < len && b[i].is_ascii_digit() {
                if digits < 9 {
                    val = val * 10 + (b[i] - b'0') as u128;
                }
                digits += 1;
                i += 1;
            }

            // 转成毫秒（3位）
            if digits > 0 {
                if digits >= 3 {
                    msecs = val / 10u128.pow((digits - 3) as u32);
                } else {
                    msecs = val * 10u128.pow((3 - digits) as u32);
                }
            }
        }


        Ok(Time {
            year,
            month,
            day,
            hour,
            minute,
            secs: second,
            msec: msecs,
            weekday: days % 7,
        })
    }

    pub fn from_common(s: impl AsRef<[u8]>) -> Result<Time, TimeError> {
        let b = s.as_ref();

        if b.len() != 19 {
            return Err(TimeError::InvalidCommon);
        }
        if b[4] != b'-' || b[7] != b'-' || b[10] != b' ' || b[13] != b':' || b[16] != b':' {
            return Err(TimeError::InvalidCommon);
        }
        let year = Time::parse_4d(&b[0..4]).ok_or(TimeError::InvalidYear)?;
        let month = Time::parse_2d(&b[5..7]).ok_or(TimeError::InvalidMonth)?;
        let day = Time::parse_2d(&b[8..10]).ok_or(TimeError::InvalidDay)?;
        let hour = Time::parse_2d(&b[11..13]).ok_or(TimeError::InvalidHour)?;
        let minute = Time::parse_2d(&b[14..16]).ok_or(TimeError::InvalidMinute)?;
        let secs = Time::parse_2d(&b[17..19]).ok_or(TimeError::InvalidSecond)?;
        let days = Time::days(year, month, day);

        Ok(Time {
            year,
            month,
            day,
            hour,
            minute,
            secs,
            msec: 0,
            weekday: days % 7,
        })
    }

    fn days(year: u128, month: u128, day: u128) -> u128 {
        let y = year - (month <= 2) as u128;
        let era = y / 400;
        let yoe = y - era * 400;
        let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    }

    pub fn as_mills(&self) -> u128 {
        let days = Time::days(self.year, self.month, self.day);
        days * Self::SECS_PER_DAY + self.hour * 3_600_000 + self.minute * 60_000 + self.secs * 1000 + self.msec
    }

    pub fn as_secs(&self) -> u128 {
        self.as_mills() / 1000
    }

    fn parse_2d(s: &[u8]) -> Option<u128> {
        let a = (s[0] as char).to_digit(10)? as u128;
        let b = (s[1] as char).to_digit(10)? as u128;
        Some(a * 10 + b)
    }

    fn parse_4d(s: &[u8]) -> Option<u128> {
        let a = (s[0] as char).to_digit(10)? as u128;
        let b = (s[1] as char).to_digit(10)? as u128;
        let c = (s[2] as char).to_digit(10)? as u128;
        let d = (s[3] as char).to_digit(10)? as u128;
        Some(a * 1000 + b * 100 + c * 10 + d)
    }
}


#[cfg(test)]
mod tests {
    use crate::time::Time;
    #[test]
    fn test_time() {
        let ts = Time::now_mills().unwrap();
        let date = Time::from_msecs(ts);
        assert_eq!(ts, date.as_mills());
        println!("{}", date.common());
        println!("{}", date.rfc1123());
        println!("{}", date.rfc3339());
        assert_eq!(Time::from_rfc1123("Thu, 26 Mar 2026 10:02:19 GMT").unwrap().as_secs(), 1774519339);
        assert_eq!(Time::from_rfc3339("2026-03-26T10:02:19.911Z").unwrap().as_mills(), 1774519339911);
        assert_eq!(Time::from_common("2026-03-26 10:02:19").unwrap().as_secs(), 1774519339);
    }
}