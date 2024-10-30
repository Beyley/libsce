pub const ErrorType = i32;
pub const NoError: ErrorType = -1;
pub const NoContentIdError: ErrorType = -2;

pub const Bool32 = enum(u32) {
    false = 0,
    true = 1,

    pub fn init(val: bool) Bool32 {
        return if (val) .true else .false;
    }
};
