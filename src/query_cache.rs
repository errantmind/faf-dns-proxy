use crate::time::timespec;

pub struct QuestionCache {
   pub asked_timestamp: timespec,
}

pub struct AnswerCache {
   pub answer: Vec<u8>,
   pub elapsed_ms: i64,
   pub ttl: u64,
}
