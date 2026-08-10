#![allow(clippy::excessive_precision)]
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use cryptoxide::hmac::Hmac;
use cryptoxide::pbkdf2;
use cryptoxide::sha2::Sha256;
use spin::Mutex;

const SALT: &[u8] = b"human-readable-checksum";
const ITERATIONS: u32 = 40000;
const CHECKSUM_LEN: usize = 5;
const KEY_BYTECOUNT: usize = 7; // ceil(5 * 11 / 8)
const MAX_CACHE_ENTRIES: usize = 5;

struct CacheEntry {
    address: String,
    phrase: String,
}

struct CheckphraseCache {
    entries: Vec<CacheEntry>,
}

impl CheckphraseCache {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Look up a cached phrase and move it to the back so it survives eviction
    /// longer (simple LRU ordering).
    fn get(&mut self, address: &str) -> Option<String> {
        for i in 0..self.entries.len() {
            if self.entries[i].address == address {
                let entry = self.entries.remove(i);
                let phrase = entry.phrase.clone();
                self.entries.push(entry);
                return Some(phrase);
            }
        }
        None
    }

    /// Insert a newly computed phrase if it is not already cached. Evict the
    /// least-recently-used entry when the cache is full.
    fn put(&mut self, address: &str, phrase: &str) {
        for entry in &self.entries {
            if entry.address == address {
                return;
            }
        }
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            self.entries.remove(0);
        }
        self.entries.push(CacheEntry {
            address: address.to_string(),
            phrase: phrase.to_string(),
        });
    }
}

static CACHE: Mutex<CheckphraseCache> = Mutex::new(CheckphraseCache::new());

/// Compute the human-readable checkphrase for an address, serving cached
/// results when available. The cache is keyed by address and is safe to keep
/// indefinitely (a firmware update naturally resets it).
pub fn from_address(ss58_address: &str) -> String {
    {
        let mut cache = CACHE.lock();
        if let Some(phrase) = cache.get(ss58_address) {
            return phrase;
        }
    }

    let phrase = from_address_uncached(ss58_address);

    CACHE.lock().put(ss58_address, &phrase);

    phrase
}

fn from_address_uncached(ss58_address: &str) -> String {
    let mut key = [0u8; KEY_BYTECOUNT];
    let mut hmac = Hmac::new(Sha256::new(), ss58_address.as_bytes());
    pbkdf2::pbkdf2(&mut hmac, SALT, ITERATIONS, &mut key);

    let mut key_int = 0u128;
    for &byte in key.iter() {
        key_int = (key_int << 8) | byte as u128;
    }
    key_int >>= (8 * KEY_BYTECOUNT) % 11;

    let mut phrase = String::new();
    for i in 0..CHECKSUM_LEN {
        let shift = (CHECKSUM_LEN - 1 - i) * 11;
        let index = ((key_int >> shift) & 0x7FF) as usize;
        if i > 0 {
            phrase.push('-');
        }
        phrase.push_str(WORDLIST[index]);
    }
    phrase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let addr = "qzpKmxWGG2prrAtgYsBT99eiPYz2teMDnMqAXNgEJqZh4DFty";
        let a = from_address(addr);
        let b = from_address(addr);
        assert_eq!(a, b);
    }

    #[test]
    fn different_addresses_different_phrases() {
        let a = from_address("qzpKmxWGG2prrAtgYsBT99eiPYz2teMDnMqAXNgEJqZh4DFty");
        let b = from_address("qzoK1UVQSssYHuTWxAN1U8egoJWRjTzF1LBcRubYp5a19ium3");
        assert_ne!(a, b);
    }

    #[test]
    fn five_words() {
        let phrase = from_address("qzpKmxWGG2prrAtgYsBT99eiPYz2teMDnMqAXNgEJqZh4DFty");
        assert_eq!(phrase.split('-').count(), 5);
    }

    #[test]
    fn matches_reference_bitcoin_satoshi() {
        let phrase = from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(phrase, "ahead-aware-sea-blockbuster-hedgehog");
    }

    #[test]
    fn cache_is_bounded_and_lru() {
        let mut cache = CheckphraseCache::new();
        for i in 0..MAX_CACHE_ENTRIES {
            cache.put(
                &alloc::format!("address-{i}"),
                &alloc::format!("phrase-{i}"),
            );
        }

        assert_eq!(cache.get("address-0").as_deref(), Some("phrase-0"));
        cache.put("address-new", "phrase-new");

        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        assert!(cache.get("address-1").is_none());
        assert_eq!(cache.get("address-0").as_deref(), Some("phrase-0"));
        assert_eq!(cache.get("address-new").as_deref(), Some("phrase-new"));
    }
}

static WORDLIST: [&str; 2048] = [
    "ability", "able", "about", "above", "absent", "absorb", "abstract", "abundance",
    "access", "acclaim", "account", "accurate", "ace", "achieve", "acoustic", "acquire",
    "across", "act", "action", "active", "actor", "actress", "actual", "adapt",
    "add", "address", "adequate", "adjust", "admire", "admit", "adopt", "adorable",
    "advance", "adventurous", "advice", "advocate", "aerobic", "affection", "affinity", "affluence",
    "afford", "again", "age", "agent", "agile", "agree", "ahead", "aid",
    "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "alight", "alive", "all", "alley", "allow", "allure", "ally",
    "almost", "alone", "alpha", "already", "also", "alter", "altruistic", "always",
    "amateur", "amazing", "ambitious", "ameliorate", "amenity", "amiable", "amicable", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anew", "angel", "angle",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "any", "appear", "apple", "approve", "april", "arch", "arctic", "ardent",
    "ardor", "area", "arena", "armor", "around", "arrange", "arrest", "arrive",
    "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "aspiration",
    "asset", "assist", "assume", "astound", "astute", "athlete", "atom", "attend",
    "attitude", "attract", "attune", "auction", "audit", "august", "aunt", "aura",
    "auspicious", "authentic", "author", "auto", "autumn", "available", "avid", "avocado",
    "awake", "aware", "away", "awe", "awesome", "axis", "baby", "bachelor",
    "backed", "badge", "bag", "balance", "balcony", "ball", "balloon", "bamboo",
    "banana", "banner", "bar", "bargain", "barn", "barrel", "base", "basic",
    "basket", "beach", "beam", "bean", "bear", "beauty", "because", "beckon",
    "become", "beetle", "befit", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "better", "between", "beyond",
    "bicycle", "bid", "big", "bike", "biology", "bird", "birth", "black",
    "blade", "blameless", "blanket", "blessing", "bliss", "blithe", "blockbuster", "bloom",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bold", "bolster", "bone", "bonus", "book", "boom", "boost",
    "border", "boring", "borrow", "boss", "bottom", "bounce", "bounty", "box",
    "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "bright", "brilliance", "bring", "brisk", "broccoli",
    "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
    "buff", "build", "bulb", "bulk", "bullish", "bundle", "buoyant", "burden",
    "burger", "burning", "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cake", "calm", "camel",
    "camera", "camp", "canal", "candy", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "carbon", "care", "carefree", "cargo", "carpet", "carry",
    "cash", "castle", "casual", "catalog", "catch", "category", "caught", "cause",
    "caution", "cave", "ceiling", "celebrate", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter",
    "charge", "chase", "chat", "check", "cheese", "chef", "cherry", "chest",
    "chic", "chief", "child", "chill", "chime", "chimney", "chivalrous", "choice",
    "choose", "chuckle", "chunk", "churn", "cinnamon", "cipher", "circle", "citizen",
    "city", "civil", "claim", "clap", "clarify", "classy", "clean", "clever",
    "click", "client", "cliff", "climb", "clinic", "clock", "clog", "close",
    "cloth", "cloud", "clown", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "cohere", "coil", "coin", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common", "company", "concert",
    "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook",
    "cool", "cooperate", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover",
    "coyote", "cozy", "cradle", "craft", "crane", "crater", "crawl", "cream",
    "credit", "creek", "cricket", "crisp", "crop", "cross", "crouch", "crowd",
    "crucial", "cruise", "crumb", "crunch", "crush", "crystal", "cube", "culture",
    "cupboard", "cure", "curious", "current", "curtain", "curve", "cushion", "custom",
    "cute", "cycle", "dad", "dance", "dank", "dao", "daring", "darling",
    "dash", "daughter", "dauntless", "dawn", "day", "dazzling", "deal", "dear",
    "debate", "debris", "decade", "december", "decent", "decide", "decorate", "decrypt",
    "dedicated", "deer", "defense", "define", "deft", "degree", "delectable", "deliver",
    "dentist", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe",
    "desert", "design", "desk", "detail", "detect", "develop", "device", "devote",
    "dew", "dextrous", "diagram", "dial", "diary", "dice", "diesel", "differ",
    "digital", "dignity", "diligent", "dinner", "dinosaur", "diplomat", "direct", "discover",
    "dish", "display", "distance", "divert", "divide", "divine", "doctor", "document",
    "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door",
    "dose", "double", "dove", "dragon", "drastic", "draw", "dream", "dress",
    "drift", "drill", "drink", "drive", "drop", "drum", "dry", "duck",
    "dune", "durable", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
    "eager", "eagle", "early", "earn", "earth", "ease", "east", "easy",
    "echo", "ecology", "economy", "ecstatic", "edge", "edit", "educate", "effective",
    "efficient", "effort", "egg", "eight", "either", "elan", "elated", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator", "elf", "elite",
    "eloquence", "else", "embark", "ember", "embody", "embrace", "emerge", "eminence",
    "emotion", "empathize", "empire", "employ", "empower", "empty", "enable", "enact",
    "enchant", "encourage", "encrypt", "endear", "endless", "endorse", "energy", "engage",
    "engine", "engrossing", "enhance", "enjoy", "enlightened", "enlist", "enough", "enrich",
    "enroll", "ensure", "enter", "entice", "entry", "envelope", "episode", "epoch",
    "equal", "equip", "erase", "ergonomic", "escape", "essay", "essence", "estate",
    "esteem", "eternal", "ethics", "euphoria", "evenly", "everlasting", "evidence", "evocative",
    "evoke", "evolve", "exact", "exalt", "example", "excess", "exchange", "excite",
    "excellent", "exemplar", "exercise", "exhibit", "exist", "exit", "exonerate", "exotic",
    "expand", "expect", "expire", "explain", "express", "exquisite", "extend", "extra",
    "exuberance", "exultant", "eyebrow", "fabric", "fabulous", "face", "facilitate", "faculty",
    "fair", "faith", "fame", "family", "famous", "fan", "fancy", "fantasy",
    "farm", "fascinate", "fashion", "fast", "father", "faucet", "faultless", "favorite",
    "fearless", "feasible", "feature", "february", "feel", "feisty", "felicity", "female",
    "fence", "fertile", "fervent", "festival", "fetch", "few", "fiber", "fiction",
    "fidelity", "field", "fiery", "figure", "film", "filter", "final", "find",
    "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish",
    "fit", "fitness", "fix", "flag", "flair", "flame", "flamingo", "flash",
    "flat", "flavor", "flawless", "flex", "flexible", "flight", "flip", "float",
    "flock", "floor", "flourish", "flower", "fluent", "fluid", "flutter", "flying",
    "foam", "focus", "fog", "fold", "follow", "fond", "food", "foolproof",
    "forest", "forget", "fork", "formidable", "fortune", "forum", "forward", "fossil",
    "foster", "found", "fox", "fragrant", "frame", "free", "frequent", "fresh",
    "friend", "frisky", "frog", "frolic", "front", "frozen", "fruit", "fuel",
    "fulfill", "fun", "funny", "furnace", "future", "gadget", "gain", "galaxy",
    "gallery", "galore", "game", "gap", "garden", "garlic", "garment", "gate",
    "gather", "gaze", "gecko", "geekier", "gem", "general", "genius", "genre",
    "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger",
    "giraffe", "girl", "give", "glad", "glamorous", "glass", "glee", "glide",
    "glimpse", "glisten", "glitter", "globe", "glory", "glove", "glow", "glue",
    "goat", "god", "goddess", "godlike", "godsend", "gold", "good", "goose",
    "gorgeous", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace",
    "grain", "grand", "grape", "grass", "grateful", "gravity", "great", "green",
    "grid", "grin", "gripping", "grit", "grocery", "group", "grow", "guard",
    "guess", "guide", "guitar", "gush", "gusto", "gutsy", "gym", "habit",
    "hail", "hair", "halcyon", "half", "hallmark", "hamster", "hand", "happy",
    "harbor", "hardy", "harmony", "harvest", "hash", "hat", "haunting", "have",
    "hawk", "head", "health", "heart", "heaven", "hedgehog", "height", "hello",
    "helmet", "help", "hen", "hero", "hidden", "high", "hilarious", "hill",
    "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "holiday",
    "hollow", "holy", "homage", "home", "honey", "honor", "hood", "hooray",
    "hope", "hoping", "horn", "horse", "hospital", "host", "hot", "hotcake",
    "hotel", "hottest", "hover", "hub", "hug", "huge", "hugs", "human",
    "humble", "humility", "humor", "hundred", "husband", "hybrid", "hydra", "ice",
    "icon", "idea", "identify", "idyllic", "illuminate", "image", "imitate", "immaculate",
    "immense", "immortal", "immune", "impact", "impeccable", "important", "impressed", "improve",
    "impulse", "inch", "include", "income", "increase", "incredible", "index", "indicate",
    "indoor", "industry", "inestimable", "infant", "influential", "inform", "ingenious", "inhale",
    "inherit", "initial", "inner", "innocent", "input", "inquiry", "inside", "inspire",
    "install", "intact", "interest", "into", "intricate", "intuitive", "invaluable", "invest",
    "invite", "involve", "invulnerable", "iron", "irreplaceable", "island", "isolate", "item",
    "ivory", "jacket", "jaguar", "jar", "jazz", "jeans", "jelly", "jellyfish",
    "jewel", "job", "join", "joke", "jolly", "journey", "jovial", "joy",
    "joyful", "joyous", "jubilant", "judicious", "juice", "jump", "jungle", "junior",
    "just", "kangaroo", "keen", "keep", "key", "keypair", "kick", "kidney",
    "kind", "kingdom", "kiss", "kitten", "kiwi", "knee", "knife", "knock",
    "know", "kudos", "label", "ladder", "lady", "lake", "lamp", "landmark",
    "language", "laptop", "large", "later", "latin", "laud", "laugh", "laundry",
    "lava", "lavender", "lavish", "lawn", "lawsuit", "layer", "leader", "leaf",
    "lean", "learn", "ledger", "legend", "leisure", "lemon", "lemur", "lend",
    "length", "lenient", "lens", "leopard", "lesson", "letter", "level", "levity",
    "liberty", "library", "lifesaver", "lift", "light", "likable", "like", "liking",
    "lily", "limb", "limit", "link", "lion", "liquid", "list", "lit",
    "live", "lizard", "load", "lobster", "local", "logic", "long", "loop",
    "lottery", "lounge", "lovable", "love", "loving", "loyal", "lucid", "lucky",
    "lucrative", "luggage", "lumber", "luminous", "lunar", "lunch", "lush", "luster",
    "luxury", "lyrics", "machine", "magic", "magnet", "main", "majestic", "major",
    "make", "mammal", "mango", "mansion", "maple", "marble", "march", "marine",
    "market", "marriage", "marvel", "mass", "master", "match", "material", "math",
    "matrix", "matter", "mature", "maximum", "maze", "meadow", "meaningful", "measure",
    "mechanic", "medal", "melody", "melt", "member", "memory", "mention", "menu",
    "mercy", "merge", "merit", "merkle", "merry", "mesh", "mesmerize", "message",
    "metal", "method", "meticulous", "midnight", "mightily", "milk", "million", "mimic",
    "mind", "mint", "minute", "miracle", "mirror", "mirth", "misery", "mist",
    "mixture", "mobile", "model", "modify", "moment", "monitor", "monkey", "month",
    "monumental", "moon", "moral", "more", "morning", "mother", "motion", "motor",
    "mountain", "mouse", "move", "much", "muffin", "multiply", "muscle", "museum",
    "mushroom", "music", "mutual", "myself", "mystery", "myth", "name", "narrow",
    "nature", "nautilus", "navigable", "near", "neat", "neck", "need", "nephew",
    "nerve", "nest", "network", "neutral", "never", "news", "next", "nice",
    "nifty", "night", "nimble", "noble", "node", "noiseless", "nominee", "noodle",
    "normal", "north", "nose", "notable", "note", "nothing", "notice", "nourish",
    "novel", "now", "nuclear", "number", "nurse", "nurturing", "nut", "oak",
    "oasis", "object", "oblige", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "octopus", "offer", "office", "often", "olive", "olympic", "once",
    "onion", "online", "only", "open", "opera", "option", "opulent", "orange",
    "orangutan", "orbit", "orchard", "order", "organ", "orient", "original", "ostrich",
    "other", "outdoor", "outer", "output", "outreach", "outside", "outwit", "oval",
    "ovation", "oven", "overjoyed", "owl", "oxygen", "oyster", "ozone", "pact",
    "paddle", "page", "painless", "pair", "palace", "palm", "panda", "panel",
    "panic", "panoramic", "panther", "paper", "parade", "pardon", "parent", "park",
    "parrot", "party", "pass", "patch", "path", "patient", "patriot", "pattern",
    "pave", "payment", "peace", "peanut", "pear", "peerless", "pelican", "pencil",
    "people", "pepper", "perfect", "permissible", "person", "pet", "phenomenal", "phone",
    "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "piety",
    "pigeon", "pilot", "pink", "pinnacle", "pioneer", "pitch", "pizza", "place",
    "planet", "plate", "play", "pleasant", "pledge", "plentiful", "pluck", "plus",
    "poem", "poetic", "poignant", "point", "poise", "polar", "polished", "pond",
    "pony", "pool", "poppy", "popular", "portion", "posh", "position", "possible",
    "post", "potato", "pottery", "power", "practice", "praise", "pray", "precious",
    "predict", "preeminent", "prefer", "premier", "prepare", "present", "pretty", "priceless",
    "primary", "print", "priority", "privilege", "prize", "proactive", "process", "produce",
    "profit", "program", "project", "prolific", "promote", "proof", "property", "prosper",
    "protect", "proud", "provide", "prowess", "prudence", "public", "pudding", "pulse",
    "pumpkin", "punctual", "pupil", "puppy", "pure", "purity", "purpose", "purse",
    "push", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick",
    "quiet", "quote", "rabbit", "raccoon", "radar", "radio", "rain", "raise",
    "rally", "ramp", "ranch", "rapid", "rapport", "rapture", "rare", "ratified",
    "raven", "raw", "razor", "reach", "ready", "reaffirm", "real", "reason",
    "rebel", "rebuild", "recall", "receive", "recipe", "reclaim", "record", "rectified",
    "redeemed", "refine", "reflect", "reform", "refresh", "regal", "region", "regular",
    "rejoice", "rejuvenate", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remunerate", "renaissance", "render", "renew", "renown", "reopen", "repair",
    "repeat", "replace", "reputable", "rescue", "resemble", "resilient", "resource", "response",
    "restful", "result", "retire", "retreat", "return", "reunion", "reveal", "review",
    "revolution", "reward", "rhythm", "ribbon", "rich", "ride", "right", "rigorous",
    "ring", "ripple", "rise", "ritual", "river", "road", "robot", "robust",
    "rocket", "rollup", "romance", "roof", "room", "rose", "rosy", "rotate",
    "rough", "round", "route", "royal", "rubber", "runway", "rural", "saddle",
    "safe", "sage", "sail", "saint", "salad", "salamander", "salient", "salmon",
    "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "save", "savings", "savvy", "scale", "scan", "scene", "school", "science",
    "scissors", "scout", "screen", "script", "sea", "seamless", "search", "season",
    "seat", "second", "secret", "section", "security", "seed", "seek", "segment",
    "select", "seminar", "senior", "sense", "sentence", "serene", "series", "service",
    "session", "setup", "seven", "shaft", "share", "shell", "shield", "shift",
    "shimmering", "shine", "ship", "shiver", "shock", "shoe", "shop", "shoulder",
    "shrimp", "shuffle", "sibling", "side", "siege", "significant", "silent", "silk",
    "silly", "silver", "similar", "simple", "sincere", "sing", "siren", "sister",
    "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin",
    "skirt", "slab", "sleep", "slender", "slick", "slide", "slot", "slush",
    "small", "smart", "smile", "smitten", "smooth", "snack", "snappy", "snazzy",
    "snow", "soap", "sober", "soccer", "social", "soft", "solar", "solid",
    "solution", "solve", "someone", "song", "soon", "soothe", "sophisticated", "sort",
    "soul", "sound", "soup", "source", "south", "sovereign", "space", "spare",
    "sparkle", "spatial", "spawn", "speak", "special", "speed", "spell", "spend",
    "sphere", "spice", "spin", "spirit", "splendid", "split", "spoil", "sponsor",
    "spoon", "sport", "spot", "spray", "spread", "spring", "square", "squeeze",
    "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stake", "stamp",
    "stand", "star", "state", "staunch", "stay", "steadfast", "steel", "stellar",
    "stem", "step", "stereo", "still", "stimulate", "stirring", "stock", "stomach",
    "stone", "story", "stout", "stove", "strategy", "street", "striking", "stroll",
    "strong", "student", "stuff", "stunning", "sturdier", "style", "suave", "subject",
    "sublime", "subsidize", "subway", "success", "such", "sudden", "suffice", "sugar",
    "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supple",
    "supply", "supreme", "superb", "sure", "surface", "surge", "surmount", "surprise",
    "surround", "survey", "sustain", "swallow", "swank", "swap", "swarm", "sweet",
    "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup",
    "system", "table", "tackle", "tact", "tag", "tail", "talent", "talk",
    "tap", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
    "ten", "tenant", "tender", "tennis", "term", "terrific", "text", "thank",
    "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrill", "thrive", "throw", "thumb", "thunder", "ticket",
    "tidy", "tiger", "tilt", "timber", "time", "tingle", "tiny", "tip",
    "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together",
    "token", "tolerant", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool",
    "tooth", "top", "topic", "topnotch", "topple", "tops", "torch", "tornado",
    "tortoise", "toss", "total", "tough", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "train", "tranquil", "travel", "tray", "treat",
    "tree", "tremendous", "trend", "trial", "tribe", "trigger", "trim", "triumph",
    "trivial", "trophy", "truck", "true", "truly", "trumpet", "trust", "truth",
    "try", "tube", "tulip", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "ultimate",
    "ultra", "umbrella", "unabashed", "unaffected", "unbeatable", "unbiased", "unbound", "uncle",
    "uncover", "undamaged", "undefeated", "undeniable", "under", "unfazed", "unfold", "unified",
    "unique", "unity", "universe", "unlimited", "unlock", "unmatched", "unparalleled", "unquestionable",
    "unreal", "unrivaled", "until", "unusual", "unveil", "unwavering", "upbeat", "update",
    "upgrade", "upheld", "uphold", "uplift", "upon", "upscale", "upside", "urban",
    "urge", "usable", "usage", "useful", "usual", "utility", "vacuum", "valid",
    "valley", "valor", "valuable", "valve", "vapor", "various", "vast", "vault",
    "vehicle", "velvet", "vendor", "venerate", "venture", "venue", "verb", "verify",
    "version", "very", "vessel", "vested", "viable", "vibrant", "victory", "video",
    "view", "vigilant", "vigor", "village", "vintage", "violin", "virtual", "visa",
    "visit", "visual", "vital", "vivacious", "vivid", "vocal", "voice", "volcano",
    "volume", "vouch", "voyage", "walk", "wall", "walnut", "want", "warm",
    "warrior", "wash", "water", "wave", "way", "wealth", "wear", "weather",
    "web", "wedding", "weekend", "welcome", "well", "west", "wet", "whale",
    "what", "wheel", "when", "where", "whisper", "whole", "wide", "wieldy",
    "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "wins", "winter", "wire", "wisdom", "wise", "wish", "witness",
    "witty", "wolf", "woman", "wombat", "won", "wonder", "wood", "wool",
    "word", "work", "world", "worth", "wow", "wrap", "wrist", "write",
    "yak", "yard", "year", "yellow", "yes", "yield", "young", "youth",
    "yummy", "zeal", "zebra", "zen", "zest", "zippy", "zone", "zoo",
];
