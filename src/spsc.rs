use std::mem;
use std::ptr;
use std::thread;
use std::clone::Clone;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Buffer<T> {
    store: *mut T,
    capacity: usize,

    head: AtomicUsize,
    tail: AtomicUsize
}

impl<T> Buffer<T> {
    fn to_ring(&self, i: usize) -> usize {
        i % self.capacity
    }
}

pub struct Consumer<T> {
    buffer: Arc<Buffer<T>>
}

pub struct Producer<T> {
    buffer: Arc<Buffer<T>>
}

unsafe impl<T: Send> Send for Consumer<T> { }
unsafe impl<T: Send> Send for Producer<T> { }

fn create<T>(capacity: usize) -> (Consumer<T>, Producer<T>) {
    unsafe {
        let _back : Box<Vec<T>> = Box::new(Vec::with_capacity(capacity));

        let internal = Buffer {
            store: mem::transmute(_back),
            capacity: capacity,

            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0)
        };

        let arc = Arc::new(internal);

        (Consumer { buffer: arc.clone() },
         Producer { buffer: arc.clone() })
    }
}

impl<T> Consumer<T> {
    fn check_pop(&self) -> bool {
        let head = self.buffer.head.load(Ordering::SeqCst);
        let tail = self.buffer.tail.load(Ordering::SeqCst);
        head != tail
    }

    pub fn try_pop(&self) -> Option<T> {
        if(self.check_pop()) {
            let ref buf = self.buffer;
            let head = buf.head.load(Ordering::SeqCst);
            let pos = buf.to_ring(head) as isize;
            let copy = unsafe { ptr::read(mem::transmute(buf.store.offset(pos))) };
            // XXX - use drop and zero-copy?
            buf.head.store(buf.to_ring(head + 1), Ordering::SeqCst);
            Some(copy)
        }
        else {
            None
        }
    }

    pub fn pop(&self) -> T {
        // XXX - make this use blocking primitives
        while(!self.check_pop()) {
            thread::sleep_ms(1);
        }
        self.try_pop().unwrap()
    }
}

impl<T> Producer<T> {
    fn check_push(&self) -> bool {
        let head = self.buffer.head.load(Ordering::SeqCst);
        let tail = self.buffer.tail.load(Ordering::SeqCst);
        head != self.buffer.to_ring(tail + 1)
    }

    pub fn push(&self, item: &T) {
        // XXX - make this use blocking primitives
        while(!self.check_push()) {
            thread::sleep_ms(1);
        }

        let ref buf = self.buffer;
        let tail = buf.tail.load(Ordering::SeqCst);
        let pos = buf.to_ring(tail) as isize;
        let copy = unsafe { ptr::copy(item, buf.store.offset(pos), 1) };
        buf.tail.store(buf.to_ring(tail + 1), Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_threaded() {
        let (c, p) = super::create(500);

        thread::spawn(move|| {
            for i in 0..10000 {
                if(i % 100 == 0) {
                    thread::sleep_ms(1);
                }
                p.push(&i);
            }
        });

        for i in 0..10000 {
            let t = c.pop();
            assert!(t == i);
        }
    }
}
