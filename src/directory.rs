use crate::record::Record;

#[derive(Default, Debug)]
pub struct Directory {
    pub records: Vec<Box<Record>>,
}

impl Directory {
    pub fn remove_record_by_name(&mut self, record_name: &str) {
        let mut index = 0;
        for record in self.records.iter() {
            if record.record_name == record_name {
                self.records.remove(index);
                break;
            }
            index += 1;
        }
    }

    pub fn remove_record(&mut self, record: &Record) {
        self.remove_record_by_name(&record.record_name);
    }
}