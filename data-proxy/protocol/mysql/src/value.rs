// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::Buf;
use chrono::{Duration, NaiveDate, NaiveDateTime, NaiveTime};

use crate::err::DecodeRowError;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<Option<T>, BoxError>;

pub trait Value: Sized {
    type Item: Convert<Self>;
    fn from(val: &[u8]) -> Result<Self>;
}

impl Value for String {
    type Item = String;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<String>>::new(val)
    }
}

impl Value for u64 {
    type Item = u64;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<u64>>::new(val)
    }
}

impl Value for Duration {
    type Item = Duration;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<Duration>>::new(val)
    }
}

impl Value for NaiveDateTime {
    type Item = NaiveDateTime;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<NaiveDateTime>>::new(val)
    }
}

impl Value for NaiveDate {
    type Item = NaiveDate;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<NaiveDate>>::new(val)
    }
}
impl Value for NaiveTime {
    type Item = NaiveTime;
    fn from(val: &[u8]) -> Result<Self> {
        <Self::Item as Convert<NaiveTime>>::new(val)
    }
}

pub trait Convert<T> {
    fn new(val: &[u8]) -> Result<T>;
}

impl Convert<String> for String {
    fn new(val: &[u8]) -> Result<String> {
        Ok(Some(String::from_utf8(val.to_vec())?))
    }
}

impl Convert<u64> for u64 {
    fn new(mut val: &[u8]) -> Result<u64> {
        Ok(Some(val.get_uint_le(val.len())))
    }
}

impl Convert<Duration> for Duration {
    fn new(mut val: &[u8]) -> Result<Duration> {
        let length = val.len();
        match length {
            8 | 12 => {
                let is_neg = val.get_u8();
                let day = val.get_uint_le(4) as i64;
                let hour = val.get_u8() as i64;
                let minute = val.get_u8() as i64;
                let second = val.get_u8() as i64;

                let mut total_micro_second: i64 =
                    (day * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second) * 1000 * 1000;

                if val.has_remaining() {
                    let micro_second = val.get_uint_le(4) as i64;
                    total_micro_second += micro_second;
                }

                if is_neg == 1 {
                    total_micro_second *= -1;
                }

                Ok(Some(Duration::microseconds(total_micro_second)))
            }

            0 => Ok(Some(Duration::seconds(0))),

            x => Err(DecodeRowError::ColumnTimeLengthInvalid(x).into()),
        }
    }
}

impl Convert<NaiveDateTime> for NaiveDateTime {
    fn new(mut val: &[u8]) -> Result<NaiveDateTime> {
        let length = val.len();
        match length {
            0 => Ok(None),

            4 => {
                let year = val.get_uint_le(2) as i32;
                let month = val.get_u8();
                let day = val.get_u8();
                let d = valid_date(year, month, day)?;
                Ok(Some(valid_datetime(d, 0, 0, 0, None)?))
            }

            7 | 11 => {
                let year = val.get_uint_le(2) as i32;
                let month = val.get_u8();
                let day = val.get_u8();
                let hour = val.get_u8();
                let minute = val.get_u8();
                let second = val.get_u8();

                let d = valid_date(year, month, day)?;

                let micro_second = if val.has_remaining() {
                    let micro_second = val.get_u32_le();
                    Some(micro_second)
                } else {
                    None
                };

                Ok(Some(valid_datetime(d, hour, minute, second, micro_second)?))
            }

            x => Err(DecodeRowError::ColumnDateTimeLengthInvalid(x).into()),
        }
    }
}

impl Convert<NaiveDate> for NaiveDate {
    fn new(mut val: &[u8]) -> Result<NaiveDate> {
        let length = val.len();
        match length {
            0 => Ok(None),

            4 | 7 | 11 => {
                let year = val.get_uint_le(2) as i32;
                let month = val.get_u8();
                let day = val.get_u8();
                let d = NaiveDate::from_ymd_opt(year, month.into(), day.into());
                Ok(d)
            }

            x => Err(DecodeRowError::ColumnDateTimeLengthInvalid(x).into()),
        }
    }
}

impl Convert<NaiveTime> for NaiveTime {
    fn new(mut val: &[u8]) -> Result<NaiveTime> {
        let length = val.len();
        match length {
            0 | 4 => Ok(None),

            7 | 11 => {
                val.advance(4);
                let hour = val.get_u8();
                let minute = val.get_u8();
                let second = val.get_u8();

                let t = if val.has_remaining() {
                    let micro_second = val.get_u32_le();
                    valid_time(hour, minute, second, Some(micro_second))?
                } else {
                    valid_time(hour, minute, second, None)?
                };

                Ok(Some(t))
            }

            x => Err(DecodeRowError::ColumnDateTimeLengthInvalid(x).into()),
        }
    }
}

fn valid_date(year: i32, month: u8, day: u8) -> std::result::Result<NaiveDate, BoxError> {
    NaiveDate::from_ymd_opt(year, month.into(), day.into()).ok_or_else(|| {
        DecodeRowError::ColumnDateTimeInvalid(format!("invalid date {year:04}-{month:02}-{day:02}"))
            .into()
    })
}

fn valid_datetime(
    date: NaiveDate,
    hour: u8,
    minute: u8,
    second: u8,
    micro_second: Option<u32>,
) -> std::result::Result<NaiveDateTime, BoxError> {
    let dt = if let Some(micro_second) = micro_second {
        date.and_hms_micro_opt(hour.into(), minute.into(), second.into(), micro_second)
    } else {
        date.and_hms_opt(hour.into(), minute.into(), second.into())
    };

    dt.ok_or_else(|| {
        DecodeRowError::ColumnDateTimeInvalid(format!(
            "invalid time {hour:02}:{minute:02}:{second:02}.{}",
            micro_second.unwrap_or(0)
        ))
        .into()
    })
}

fn valid_time(
    hour: u8,
    minute: u8,
    second: u8,
    micro_second: Option<u32>,
) -> std::result::Result<NaiveTime, BoxError> {
    let time = if let Some(micro_second) = micro_second {
        NaiveTime::from_hms_micro_opt(hour.into(), minute.into(), second.into(), micro_second)
    } else {
        NaiveTime::from_hms_opt(hour.into(), minute.into(), second.into())
    };

    time.ok_or_else(|| {
        DecodeRowError::ColumnTimeInvalid(format!(
            "invalid time {hour:02}:{minute:02}:{second:02}.{}",
            micro_second.unwrap_or(0)
        ))
        .into()
    })
}

#[cfg(test)]
mod test {
    use super::Value;

    fn to_string<T: Value>(val: &[u8]) -> Option<T> {
        Value::from(val).unwrap()
    }

    #[test]
    fn test_to_string() {
        let data: Vec<u8> = vec![78, 111];

        let res = to_string::<String>(&data);
        assert_eq!(res, Some("No".to_string()));
    }
}
