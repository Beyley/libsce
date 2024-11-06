const std = @import("std");

const Self = @This();

const GetSeekPosError = error{};
const ReadError = error{};
const SeekError = error{};
const WriteError = std.mem.Allocator.Error || error{};

array_list: std.ArrayList(u8),
pos: u64,

pub const Reader = std.io.GenericReader(*Self, ReadError, read);
pub const Writer = std.io.GenericWriter(*Self, WriteError, write);
pub const SeekableStream = std.io.SeekableStream(
    *Self,
    SeekError,
    GetSeekPosError,
    seekTo,
    seekBy,
    getPos,
    getEndPos,
);

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .array_list = .init(allocator),
        .pos = 0,
    };
}

pub fn deinit(self: Self) void {
    self.array_list.deinit();
}

pub fn getEndPos(self: *Self) GetSeekPosError!u64 {
    return self.array_list.items.len;
}

pub fn getPos(self: *Self) GetSeekPosError!u64 {
    return self.pos;
}

pub fn read(self: *Self, dest: []u8) ReadError!usize {
    //Get the amount of bytes to be read
    const amount_read: usize = @intCast(@min(dest.len, self.array_list.items.len - self.pos));

    //Copy the data into the output
    @memcpy(dest, self.array_list.items[self.pos .. self.pos + amount_read]);

    //Increment the position
    self.pos += @intCast(amount_read);

    //Return the amount of data read
    return amount_read;
}

pub fn seekBy(self: *Self, amt: i64) SeekError!void {
    if (amt >= 0)
        self.pos += @intCast(amt)
    else
        self.pos -= @abs(amt);
}

pub fn seekTo(self: *Self, pos: u64) SeekError!void {
    self.pos = pos;
}

pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
    const end_pos = self.pos + bytes.len;

    const cur_capacity = self.array_list.capacity;

    //Make sure all the data can fit
    try self.array_list.ensureTotalCapacity(end_pos);

    // If the new capacity is greater than the current capacity, memset the new contents to zero
    if (self.array_list.capacity > cur_capacity) {
        var full_arr = self.array_list.items;
        full_arr.len = self.array_list.capacity;
        @memset(full_arr[cur_capacity..], 0);
    }

    //Make sure the length of the slice is correct
    self.array_list.items.len = @max(end_pos, self.array_list.items.len);

    //Copy the data into the array list
    @memcpy(self.array_list.items[self.pos..end_pos], bytes);

    self.pos += bytes.len;

    return bytes.len;
}

pub fn reader(self: *Self) Reader {
    return .{ .context = self };
}

pub fn writer(self: *Self) Writer {
    return .{ .context = self };
}

pub fn seekableStream(self: *Self) SeekableStream {
    return .{ .context = self };
}
