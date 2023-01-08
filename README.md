```figlet
 ____  _                         _
|  _ \(_) ___ ___ __/\__     ___(_) __ _
| |_) | |/ __/ _ \\    /____|_  / |/ _` |
|  __/| | (_| (_) /_  _\_____/ /| | (_| |
|_|   |_|\___\___/  \/      /___|_|\__, |
                                   |___/
```

[`Pico*`](https://github.com/telamon/picostack) is coming to Zig!


Discord: https://discord.gg/8RMRUPZ9RS
### Status [PicoFeed](https://github.com/telamon/picofeed)

| ES6           | status | Remark                                        |
|:--------------|:------:|:----------------------------------------------|
| Feed.new()    |  done  |                                               |
| Feed.from()   |  done  | Refactored into wrap(),unpickle(),create()    |
| f.append()    |  done  |                                               |
| f.inspect()   |  done  |                                               |
| f.get(n)      |  done  | f.blockAt()                                   |
| f.getKey(n)   |   --   | use f.keys()                                  |
| f.last        |  done  | f.lastBlock()                                 |
| f.first       |  done  | f.firstBlock()                                |
| f.index()     |  done  | f.iterator() // does not validate signatures. |
| f.trunacte()  |  todo  |                                               |
| f.diff()      |  todo  |                                               |
| f.merge()     |  todo  |                                               |
| f.pickle()    |  todo  |                                               |
| WASM-bindings |  todo  | must pass existing test-suite                 |


### Status [PicoRepo](https://github.com/telamon/picorepo)
TBD


### Usage

Workflow is still theoretical, refer to status table or zigdoc for now.
```zig
const std = require('std');
const pico = require('lib/pico/main.zig');
const Feed = pico.Feed;

pub fn main (): void {
  const allocator = std.heap.page_allocator;
  // Create a writable feed.
  const writable_feed = Feed.create(allocator);
  defer writable_feed.deinit(); // writable feeds must be freed.

  var pair = try Feed.signPair();
  const sk: [64]u8 = pair.secret_key.bytes;

  // Append a block to feed
  try f.append("Hello Cosmos", sk);
  try f.append("We've hit a snag", sk);

  f.inspect(); // => prints contents to stderr

  // Create a readonly feed from pickled string.
  const readable_feed = try Feed.unpickle("PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U");

  readable_feed.inspect();

  // Interact with remote feeds
  const multi_author = Feed.create(allocator);
  defer multi_author.deinit();
  try multi_author.merge(readable_feed);
  try multi_author.append("Approved!", sk);
  f.pickle() // => "PIC0.K0.....";
}
```

### demo

```
feed.inspect();
. .________________________________. .
| |    PiC0FEED G K01 B02 309B     | |
|¤|________________________________|¤|
| |KEY 0: 87f9a8f7008a228a...a1c3ae| |
|¤|________________________________|¤|
| |BLOCK 0                       5B| |
|¤| 000000000000  <=  554674dadef2 |¤|
| |................................| |
|¤|48 65 6c 6c 6f          Hello   |¤|
| |________________________________| |
|¤|BLOCK 1                       5B|¤|
| | 554674dadef2  <=  5e21d30c3a1c | |
|¤|................................|¤|
| |57 6f 72 6c 64          World   | |
|¤|________________________________|¤|
. .                                . .
```
---
Licsense: AGPLv3 | DecentLabs 2023
