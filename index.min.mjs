var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/index.ts
import * as fs6 from "fs";
import * as path3 from "path";

// src/utils/lock.ts
import * as crypto from "crypto";

// src/utils/belaMessage.ts
import chalk from "chalk";
var BELAMessage = class {
  static say(data = {
    type: "error",
    code: 404,
    name: "Error",
    version: "v0.0.4-dev",
    message: "There is an error."
  }) {
    const version = "v0.0.4-dev";
    const underlineRegex = /_(.*?)_/g;
    const boldRegex = /\*(.*?)\*/g;
    const formattedMessage = data.message.replace(underlineRegex, (_, text) => chalk.underline(text)).replace(boldRegex, (_, text) => chalk.bold(text));
    const formattedStack = data.stack ? data.stack.replace(/[•\-–—]/g, (match) => chalk.grey(match)).replace(underlineRegex, (_, text) => chalk.underline(text)).replace(boldRegex, (_, text) => chalk.bold(text)) + `
  ${chalk.grey("\u2022")} ${data.name} ${chalk.bold.underline(data.version ?? version)}
` : `  ${chalk.grey("\u2022")} ${data.name} ${chalk.bold.underline(data.version ?? version)}
`;
    if (data.type === "error") {
      console.log(
        `${chalk.cyan(data.name)} - ${chalk.red(data.type)} ${chalk.grey(data.code + ":")} ${formattedMessage}
${formattedStack}`
      );
      return "";
      process.exit(1);
    } else if (data.type === "success") {
      console.log(
        `${chalk.cyan(data.name)} - ${chalk.green(data.type)} ${chalk.grey(data.code + ":")} ${formattedMessage}
${formattedStack}`
      );
      return "";
    } else if (data.type === "epoch") {
      console.log(
        `${chalk.cyan(data.name)} - ${chalk.green(data.type)} ${chalk.grey(data.code + ":")} ${formattedMessage}`
      );
      return "";
    } else if (data.type === "test") {
      console.log(
        `${chalk.cyan(data.name)} - ${chalk.green(data.type)} ${chalk.grey(data.code + ":")} ${formattedMessage}`
      );
      return "";
    } else if (data.type === "other_warning") {
      return `${chalk.cyan(data.name)} - ${chalk.yellow("warning")} ${chalk.grey(data.code + ":")} ${formattedMessage}`;
    } else {
      console.log(`Invalid type ${data.type}`);
      return "";
      process.exit(1);
    }
  }
};

// src/utils/lock.ts
var ALGORITHM = "aes-256-cbc";
var IV = crypto.randomBytes(16);
var KEY;
function encrypt(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, IV);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${IV.toString("hex")}:${encrypted}`;
}
function base64(text) {
  return Buffer.from(text).toString("base64");
}
function lock(json, password, modelName) {
  KEY = getFullEnv(password);
  let encoded = encrypt(JSON.stringify(json));
  for (let i = 0; i < 10; i++) {
    encoded = base64(encoded);
  }
  let code = "";
  try {
    return encrypt(encoded);
  } catch (err) {
    if (modelName) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B2E2" /* INTERNAL_CORRUPTED_PROBLEM */,
        name: "BELA",
        message: `Failed to save model with name _*${modelName}*_.`
      });
    }
    return "";
  }
}

// src/utils/unlock.ts
import crypto2 from "crypto";

// src/default/modelData.ts
var modelData = {
  parameters: {
    epochs: 0,
    learningRate: 0,
    momentum: 0,
    randomness: 0,
    nGramOrder: 0,
    layers: [0, 0, 0]
  },
  learnedPatterns: [],
  binaryPatterns: [],
  frequentPatterns: [],
  reverseNGrams: {}
};

// src/default/metadata.ts
var metadata = {
  name: "",
  version: "",
  author: "",
  description: "",
  timestamp: /* @__PURE__ */ new Date()
};

// src/utils/unlock.ts
var ALGORITHM2 = "aes-256-cbc";
var IV2 = crypto2.randomBytes(16);
var KEY2;
function decrypt(encryptedText) {
  try {
    const [ivHex, encrypted] = encryptedText.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto2.createDecipheriv(ALGORITHM2, KEY2, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    return "";
  }
}
function base642(encodedText) {
  return Buffer.from(encodedText, "base64").toString("utf8");
}
function isValid(code) {
  if (code.length !== 16) return false;
  const raw = code.slice(0, 12);
  const expectedChecksum = generateChecksum(raw);
  const actualChecksum = code.slice(12);
  return expectedChecksum === actualChecksum;
}
function generateChecksum(input) {
  let sum = 0;
  for (let i = 0; i < input.length; i++) {
    sum += input.charCodeAt(i) * (i + 1);
  }
  const hash = sum.toString().padStart(4, "0").slice(-4);
  return hash;
}
function unlock(encodedText, key, modelName) {
  KEY2 = key;
  let decoded = decrypt(encodedText);
  for (let i = 0; i < 10; i++) {
    decoded = base642(decoded);
  }
  let authenticity = false;
  try {
    const code = encodedText.slice(-16);
    if (isValid(code)) {
      authenticity = true;
      return JSON.parse(decrypt(decoded.replace(code, "")));
    } else {
      authenticity = false;
      throw new Error("");
    }
  } catch (err) {
    if (modelName) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B2E2" /* INTERNAL_CORRUPTED_PROBLEM */,
        name: "BELA",
        message: `Failed to load model with name _*${modelName}*_.`,
        stack: `  \u2022 ${authenticity ? "" : "File not authentic."}`
      });
    }
    return modelData;
  }
}

// src/utils/converter.ts
var vocabMap = /* @__PURE__ */ new Map();
var unkTokenId = -1;
function setVocab(vocab) {
  vocabMap.clear();
  vocab.forEach((word, idx) => {
    vocabMap.set(word, idx);
    if (word === "<unk>") {
      unkTokenId = idx;
    }
  });
}
function wordToToken(word) {
  if (!vocabMap.has(word)) {
    if (unkTokenId === -1) {
      throw new Error(`Unknown token: ${word} (no <unk> token set)`);
    }
    return String(unkTokenId);
  }
  return String(vocabMap.get(word));
}
function tokenToWord(token) {
  const id = parseInt(token);
  for (const [word, idx] of vocabMap.entries()) {
    if (idx === id) {
      return word;
    }
  }
  if (unkTokenId !== -1) {
    return "<unk>";
  }
  throw new Error(`Unknown token id: ${token}`);
}
function wordToBinary(text) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const binary = Array.from(bytes).map((byte) => byte.toString(2).padStart(8, "0")).join("");
  return binary;
}
function binaryToWord(binary) {
  if (binary.length % 8 !== 0) {
    throw new Error("Binary length must be multiple of 8");
  }
  const bytes = [];
  for (let i = 0; i < binary.length; i += 8) {
    const byte = binary.slice(i, i + 8);
    bytes.push(parseInt(byte, 2));
  }
  const decoder = new TextDecoder();
  return decoder.decode(new Uint8Array(bytes));
}

// src/utils/calculateHammingDistance.ts
function calculateHammingDistance(binary1, binary2) {
  let minLength = Math.min(binary1.length, binary2.length);
  let distance = Math.abs(binary1.length - binary2.length);
  for (let i = 0; i < minLength; i++) {
    if (binary1[i] !== binary2[i]) distance++;
  }
  return distance;
}

// src/utils/isConversationDataset.ts
var isConversationDataset = (dataset) => typeof dataset[0] === "object" && dataset[0] !== null && "input" in dataset[0] && "output" in dataset[0];

// src/utils/isImageDataset.ts
var isImageDataset = (dataset) => typeof dataset[0] === "object" && dataset[0] !== null && "title" in dataset[0] && "image" in dataset[0];

// src/utils/getDistribution.ts
function getDistribution(binary) {
  return binary.split("").reduce((acc, bit) => (acc[bit] = (acc[bit] || 0) + 1, acc), { "0": 0, "1": 0 });
}

// src/utils/getFullEnv.ts
function getFullEnv(key) {
  const maxRetries = 5;
  for (let i = 0; i < maxRetries; i++) {
    if (key && key?.length === 32) {
      return key;
    }
  }
  throw BELAMessage.say({
    type: "error" /* ERROR */,
    code: "B1E1" /* GENERAL_NOT_FULFILLED */,
    name: "BELA",
    message: `Password length must be 32, but got ${key?.length}.`
  });
}

// src/utils/incrementBelamodel.ts
import * as fs from "fs";
import * as path from "path";
function incrementBelamodel(dirPath, modelName, newData, key) {
  const files = fs.readdirSync(dirPath);
  const regex = new RegExp(`^${modelName}-(\\d+)\\.belamodel$`);
  let maxNumber = 0;
  let latestFile = null;
  files.forEach((file) => {
    let match = file.match(regex);
    if (match) {
      let num = Number(match[1]);
      if (num > maxNumber) {
        maxNumber = num;
        latestFile = file;
      }
    }
  });
  if (latestFile) {
    const latestFilePath = path.join(dirPath, latestFile);
    const latestData = unlock(fs.readFileSync(latestFilePath, "utf-8"), key);
    if (JSON.stringify(latestData) === JSON.stringify(newData)) {
      return latestFile;
    }
  }
  let newNumber = String(maxNumber + 1).padStart(3, "0");
  return `${modelName}-${newNumber}.belamodel`;
}

// src/utils/deleteBelamodel.ts
import * as fs2 from "fs";
function deleteBelamodel(dirPath, modelName, maxFiles) {
  const files = fs2.readdirSync(dirPath);
  const regex = new RegExp(`^${modelName}-(\\d+)\\.belamodel$`);
  let fileNumbers = [];
  files.forEach((file) => {
    let match = file.match(regex);
    if (match) {
      fileNumbers.push(Number(match[1]));
    }
  });
  if (fileNumbers.length > maxFiles) {
    let minNumber = Math.min(...fileNumbers);
    return `${modelName}-${String(minNumber).padStart(3, "0")}.belamodel`;
  }
  return null;
}

// src/utils/getLatestBelamodel.ts
import * as fs3 from "fs";
function getLatestBelamodel(dirPath, modelName) {
  const files = fs3.readdirSync(dirPath);
  const regex = new RegExp(`^${modelName}-(\\d+)\\.belamodel$`);
  let maxNumber = 0;
  let latestFile = null;
  files.forEach((file) => {
    let match = file.match(regex);
    if (match) {
      let num = Number(match[1]);
      if (num > maxNumber) {
        maxNumber = num;
        latestFile = file;
      }
    }
  });
  return latestFile;
}

// src/utils/getModelNumber.ts
function getModelNumber(filename, modelName) {
  const regex = new RegExp(`^${modelName}-(\\d+)\\.belamodel$`);
  const match = filename.match(regex);
  return match ? match[1].padStart(3, "0") : null;
}

// src/utils/findSimilarFile.ts
import fs4 from "fs";
function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        // Hapus
        matrix[i][j - 1] + 1,
        // Tambah
        matrix[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        // Ganti
      );
    }
  }
  return matrix[a.length][b.length];
}
function cleanFileName(fileName) {
  return fileName.replace(/-\d+\.belamodel$/, "");
}
function findSimilarFile(folder, inputName) {
  const files = fs4.readdirSync(folder);
  let bestMatch = { file: null, distance: Infinity };
  const cleanedInput = cleanFileName(inputName);
  const maxDistance = Math.max(1, Math.min(5, Math.floor(cleanedInput.length * 0.2)));
  for (const file of files) {
    const cleanedFile = cleanFileName(file);
    if (cleanedFile.includes(cleanedInput)) {
      return file;
    }
    const distance = levenshtein(cleanedInput, cleanedFile);
    if (distance < bestMatch.distance && distance <= maxDistance) {
      bestMatch = { file, distance };
    }
  }
  return bestMatch.file;
}

// src/utils/question.ts
import * as readline from "readline";
var question = (message) => {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    const ask = () => {
      const formattedQuestion = BELAMessage.say({
        type: "other_warning" /* OTHER_WARNING */,
        code: "B4W1" /* WARNING_CHOICE_ACTION */,
        name: "BELA",
        message
      });
      rl.question(formattedQuestion + " (yes/no) ", (answer) => {
        const lowerAnswer = answer.trim().toLowerCase();
        if (lowerAnswer === "yes") {
          rl.close();
          resolve(true);
        } else if (lowerAnswer === "no") {
          rl.close();
          resolve(false);
        } else {
          ask();
        }
      });
    };
    ask();
  });
};

// src/utils/tokenize.ts
function tokenize(text, vocabs, maxToken) {
  const words = text.split(" ");
  const tokens = [];
  for (let word of words) {
    let remaining = word.toLowerCase();
    let token = "\u2581";
    while (remaining.length > 0) {
      let found = false;
      for (let i = Math.min(remaining.length, maxToken); i > 0; i--) {
        const sub = remaining.slice(0, i);
        if (vocabs.includes(sub)) {
          const t = token + sub;
          tokens.push(wordToToken(t));
          remaining = remaining.slice(i);
          token = "";
          found = true;
          break;
        }
      }
      if (!found) {
        const t = token + remaining[0];
        tokens.push(wordToToken(t));
        remaining = remaining.slice(1);
        token = "";
      }
    }
  }
  return tokens;
}

// src/utils/detokenize.ts
function detokenize(tokens) {
  let words = [];
  let currentWord = "";
  for (let token of tokens) {
    const wordPiece = tokenToWord(token);
    console.log({ token, wordPiece });
    if (wordPiece.startsWith("\u2581")) {
      if (currentWord.length > 0) {
        words.push(currentWord);
      }
      currentWord = wordPiece.slice(1);
    } else {
      currentWord += wordPiece;
    }
  }
  if (currentWord.length > 0) {
    words.push(currentWord);
  }
  return words.join(" ");
}

// src/utils/softmax.ts
function softmax(scores) {
  const maxScore = Math.max(...scores);
  const exps = scores.map((s) => Math.exp(s - maxScore));
  const sumExp = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sumExp);
}

// src/utils/similarity.ts
function similarity(a, b) {
  if (a.length !== b.length) return 0;
  let score = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) score++;
  }
  return score;
}

// src/conversation/PatternTrainer.ts
var PatternTrainer = class {
  constructor(nGramOrder, learningRate, momentum, layers) {
    this.nGramOrder = nGramOrder;
    this.learningRate = learningRate;
    this.momentum = momentum;
    this.layers = layers;
    this.binaryPatterns = /* @__PURE__ */ new Map();
    this.invalidPatterns = /* @__PURE__ */ new Set();
    this.frequentPatterns = /* @__PURE__ */ new Set();
  }
  nGramPatterns = /* @__PURE__ */ new Map();
  totalNGrams = /* @__PURE__ */ new Map();
  reverseNGrams = {};
  learnedPatterns = /* @__PURE__ */ new Map();
  binaryPatterns;
  invalidPatterns;
  frequentPatterns;
  wordAssociations = /* @__PURE__ */ new Map();
  punctuationStats = /* @__PURE__ */ new Map();
  binaryAttention = /* @__PURE__ */ new Map();
  learnSentence(sentence, vocab, maxSubstringToken) {
    this.learnNGrams(sentence, vocab, maxSubstringToken);
    const words = tokenize(
      sentence,
      vocab,
      maxSubstringToken
    );
    for (let i = 0; i < words.length; i++) {
      words[i] = wordToBinary(words[i]);
    }
    for (let i = 0; i < words.length - 1; i++) {
      const word = words[i];
      const nextWord = words[i + 1];
      if (!this.learnedPatterns.has(word)) {
        this.learnedPatterns.set(word, { nextWords: /* @__PURE__ */ new Map(), totalNextWords: 0 });
      }
      const pattern = this.learnedPatterns.get(word);
      if (!pattern || !(pattern.nextWords instanceof Map)) {
        throw BELAMessage.say({
          type: "error" /* ERROR */,
          code: "B2E2" /* INTERNAL_CORRUPTED_PROBLEM */,
          name: "BELA",
          message: "Corrupted learned patterns."
        });
      }
      const layerFactor = this.layers.length;
      pattern.nextWords.set(nextWord, (pattern.nextWords.get(nextWord) || 0) + this.learningRate * layerFactor);
      pattern.totalNextWords += this.learningRate * layerFactor;
    }
    this.learnContextualPatterns(words);
  }
  learnNGrams(sentence, vocab, maxSubstringToken) {
    const words = tokenize(sentence, vocab, maxSubstringToken);
    const maxPossibleN = words.length - 1;
    for (let n = 1; n <= maxPossibleN; n++) {
      for (let i = 0; i <= words.length - n - 1; i++) {
        const contextWords = words.slice(i, i + n);
        const nextWord = words[i + n];
        const kVectors = contextWords.map((w) => wordToBinary(w));
        const qVector = wordToBinary(nextWord);
        const attentionScores = kVectors.map((kVec) => similarity(kVec, qVector));
        const attentionWeights = softmax(attentionScores);
        const wordWeightPairs = contextWords.map((w, idx) => `${w}:${attentionWeights[idx].toFixed(3)}`);
        const nGramKey = wordWeightPairs.join(" | ");
        const entropy = -attentionWeights.reduce((acc, w) => acc + w * Math.log2(w || 1e-8), 0);
        if (entropy > Math.log2(contextWords.length)) continue;
        if (!this.nGramPatterns.has(nGramKey)) {
          this.nGramPatterns.set(nGramKey, /* @__PURE__ */ new Map());
          this.totalNGrams.set(nGramKey, 0);
        }
        const pattern = this.nGramPatterns.get(nGramKey);
        pattern.set(nextWord, (pattern.get(nextWord) || 0) + 1);
        this.totalNGrams.set(nGramKey, this.totalNGrams.get(nGramKey) + 1);
      }
    }
  }
  getReverseNGram(sentence, vocab, maxSubstringToken) {
    const words = tokenize(sentence, vocab, maxSubstringToken);
    for (let i = 1; i < words.length; i++) {
      const currentWord = words[i];
      const contextWords = words.slice(Math.max(0, i - this.nGramOrder), i);
      const attentionScores = contextWords.map((w) => w === currentWord ? 1 : 0);
      const attentionWeights = softmax(attentionScores);
      const contextWeighted = contextWords.map((w, idx) => `${w}:${attentionWeights[idx].toFixed(3)}`);
      const key = contextWeighted.join(" | ");
      if (!this.reverseNGrams[currentWord]) {
        this.reverseNGrams[currentWord] = /* @__PURE__ */ new Map();
      }
      const reverseMap = this.reverseNGrams[currentWord];
      reverseMap.set(key, (reverseMap.get(key) ?? 0) + 1);
    }
  }
  getMostLikelyWord(candidates) {
    if (!candidates.length) return null;
    let wordCount = {};
    for (let word of candidates) {
      wordCount[word] = (wordCount[word] || 0) + 1;
    }
    let sortedWords = Object.entries(wordCount).sort((a, b) => b[1] - a[1]);
    return sortedWords[0][0];
  }
  getPredictionConfidence(word) {
    const pattern = this.learnedPatterns.get(word);
    if (!pattern) return 0;
    let maxFreq = 0;
    for (let val of pattern.nextWords.values()) {
      if (val > maxFreq) maxFreq = val;
    }
    return maxFreq / pattern.totalNextWords;
  }
  learnContextualPatterns(words) {
    const contextWindow = 2;
    for (let i = 0; i < words.length; i++) {
      const wordBinary = wordToBinary(words[i]);
      const leftContext = words.slice(Math.max(0, i - contextWindow), i).map(wordToBinary);
      const rightContext = words.slice(i + 1, Math.min(words.length, i + 1 + contextWindow)).map(wordToBinary);
      const context = [...leftContext, ...rightContext];
      if (!this.wordAssociations.has(wordBinary)) {
        this.wordAssociations.set(wordBinary, /* @__PURE__ */ new Map());
      }
      const map = this.wordAssociations.get(wordBinary);
      for (const ctxBinary of context) {
        const associationWeight = 1;
        map.set(ctxBinary, (map.get(ctxBinary) || 0) + associationWeight);
      }
    }
  }
};

// src/conversation/PatternPredictor.ts
var PatternPredictor = class {
  constructor(trainer, matching, randomness) {
    this.trainer = trainer;
    this.matching = matching;
    this.randomness = randomness;
  }
  predictNextWord(word) {
    if (Math.random() < this.randomness) {
      const allWords2 = Array.from(this.trainer.learnedPatterns.keys());
      return allWords2.length > 0 ? allWords2[Math.floor(Math.random() * allWords2.length)] : null;
    }
    const tokens = word.split(" ");
    const scoreMap = /* @__PURE__ */ new Map();
    for (let n = tokens.length; n >= 1; n--) {
      const contextWords = tokens.slice(-n);
      const queryWord = tokens[tokens.length - 1];
      const attentionScores = contextWords.map((k) => k === queryWord ? 1 : 0);
      const attentionWeights = softmax(attentionScores);
      const wordWeightPairs = contextWords.map((w, idx) => `${w}:${attentionWeights[idx].toFixed(3)}`);
      const contextKey = wordWeightPairs.join(" | ");
      const pattern = this.trainer.nGramPatterns.get(contextKey);
      if (!pattern) continue;
      for (let [nextWord, freq] of pattern.entries()) {
        const score = Math.log(freq + 1);
        scoreMap.set(nextWord, (scoreMap.get(nextWord) ?? 0) + score * 1);
      }
    }
    const binaryWord = wordToToken(word);
    if (this.trainer.wordAssociations.has(binaryWord)) {
      const contextMap = this.trainer.wordAssociations.get(binaryWord);
      for (let [assocBinary, freq] of contextMap.entries()) {
        const assocWord = tokenToWord(assocBinary);
        if (!assocWord) continue;
        const score = Math.log(freq + 1);
        scoreMap.set(assocWord, (scoreMap.get(assocWord) ?? 0) + score * 1);
      }
    }
    const attentionMap = this.trainer.binaryAttention.get(binaryWord);
    if (attentionMap) {
      for (let [assocBinary, attentionScore] of attentionMap.entries()) {
        const assocWord = tokenToWord(assocBinary);
        if (!assocWord) continue;
        const score = attentionScore;
        scoreMap.set(assocWord, (scoreMap.get(assocWord) ?? 0) + score * 1.2);
      }
    }
    const sorted = Array.from(scoreMap.entries()).sort((a, b) => b[1] - a[1]);
    if (sorted.length > 0) return sorted[0][0];
    const allWords = Array.from(this.trainer.learnedPatterns.keys());
    return allWords.length > 0 ? allWords[Math.floor(Math.random() * allWords.length)] : null;
  }
  generateSentence(inputSentence, maxLength = 10) {
    const startWord = this.getContextFromSentence(inputSentence);
    let sentence = [startWord];
    let currentWord = startWord;
    for (let i = 0; i < maxLength - 1; i++) {
      const nextWord = this.predictNextWord(currentWord);
      if (!nextWord) break;
      const prevWord = this.predictPrevWord(currentWord);
      let contextWord = currentWord;
      if (prevWord) {
        contextWord = prevWord + " " + currentWord;
      }
      const confidence = this.trainer.getPredictionConfidence(contextWord);
      if (confidence < 0.05) break;
      sentence.push(nextWord);
      currentWord = nextWord;
    }
    return sentence;
  }
  predictBinaryOutput(inputBinary) {
    if (this.trainer.binaryPatterns.size === 0) {
      throw BELAMessage.say({
        type: "success" /* SUCCESS */,
        code: 404,
        name: "BELA",
        message: "No patterns learned yet!"
      });
    }
    const closestPattern = this.matching.findClosestPattern(inputBinary);
    return closestPattern ? this.trainer.binaryPatterns.get(closestPattern).output : null;
  }
  predictPrevWord(currentWord) {
    if (!currentWord) return null;
    let candidates = this.trainer.reverseNGrams[currentWord];
    if (!candidates || candidates.length === 0) return null;
    return this.trainer.getMostLikelyWord(candidates);
  }
  getContextFromSentence(tokens) {
    const maxOrder = this.trainer.nGramOrder ?? 3;
    if (tokens.length === 0) return "";
    const context = tokens.slice(-maxOrder).join(" ");
    return context;
  }
};

// src/conversation/PatternMatching.ts
var PatternMatching = class {
  constructor(trainer) {
    this.trainer = trainer;
  }
  synonymMap = /* @__PURE__ */ new Map([
    ["baik", ["bagus", "mantap", "positif"]],
    ["buruk", ["jelek", "negatif", "gak bagus"]]
  ]);
  findClosestPattern(inputBinary) {
    let closestPattern = null;
    let closestDistance = Infinity;
    for (let [binary] of this.trainer.binaryPatterns) {
      const distance = calculateHammingDistance(
        inputBinary,
        binary
      );
      if (distance < closestDistance) {
        closestDistance = distance;
        closestPattern = binary;
      }
    }
    return closestPattern;
  }
  findClosestWord(inputWord) {
    if (this.synonymMap.has(inputWord)) {
      return this.synonymMap.get(inputWord)[0];
    }
    let closestWord = null;
    let minDistance = Infinity;
    for (let word of this.trainer.learnedPatterns.keys()) {
      const distance = calculateHammingDistance(
        wordToBinary(inputWord),
        wordToBinary(word)
      );
      if (distance < minDistance) {
        minDistance = distance;
        closestWord = word;
      }
    }
    return closestWord;
  }
};

// src/conversation/ModelManager.ts
import * as fs5 from "fs";
import * as path2 from "path";
var ModelManager = class {
  constructor(trainer, epochs, learningRate, momentum, randomness, nGramOrder, layers, packageRoot, pathRoot, pathModel, pathBackup) {
    this.trainer = trainer;
    this.epochs = epochs;
    this.learningRate = learningRate;
    this.momentum = momentum;
    this.randomness = randomness;
    this.nGramOrder = nGramOrder;
    this.layers = layers;
    this.packageRoot = packageRoot;
    this.pathRoot = pathRoot;
    this.pathModel = pathModel;
    this.pathBackup = pathBackup;
  }
  currentModel = modelData;
  filename = "";
  password = "";
  save(modelName, password, maxFile, autoDelete, metadata2) {
    const modelData2 = {
      metadata: metadata2,
      parameters: {
        epochs: this.epochs,
        learningRate: this.learningRate,
        momentum: this.momentum,
        randomness: this.randomness,
        nGramOrder: this.nGramOrder,
        layers: this.layers
      },
      learnedPatterns: Array.from(this.trainer.learnedPatterns.entries()),
      binaryPatterns: Array.from(this.trainer.binaryPatterns.entries()),
      frequentPatterns: Array.from(this.trainer.frequentPatterns),
      reverseNGrams: this.trainer.reverseNGrams
    };
    const saveFilename = incrementBelamodel(path2.join(this.packageRoot, this.pathModel), modelName, modelData2, password);
    const saveModelPath = path2.join(this.packageRoot, this.pathRoot, this.pathModel, saveFilename);
    this.filename = saveFilename ?? "/";
    const modelNumber = getModelNumber(this.filename, modelName);
    if (fs5.existsSync(saveModelPath)) {
      BELAMessage.say({
        type: "success" /* SUCCESS */,
        code: "B3S2" /* SUCCESS_ALREADY_EXISTS */,
        name: "BELA",
        message: `Model with name _*${modelName}*_ and version _*${modelNumber}*_ already exists.`
      });
      return;
    }
    fs5.writeFileSync(saveModelPath, lock(modelData2, password, modelName), "utf8");
    if (autoDelete) {
      const deleteFilename = deleteBelamodel(
        path2.join(
          this.packageRoot,
          this.pathModel
        ),
        modelName,
        maxFile
      );
      if (deleteFilename) {
        const deleteModelPath = path2.join(
          this.packageRoot,
          this.pathRoot,
          this.pathModel,
          deleteFilename
        );
        fs5.unlinkSync(deleteModelPath);
      }
    }
    BELAMessage.say({
      type: "success" /* SUCCESS */,
      code: "B3S1" /* SUCCESS_TAKE_ACTION */,
      name: "BELA",
      message: `Successfully saved model with name _*${modelName}*_ and version _*${modelNumber}*_.`
    });
  }
  load(modelName, password) {
    this.filename = getLatestBelamodel(
      path2.join(
        this.packageRoot,
        this.pathModel
      ),
      modelName
    ) ?? "";
    this.password = password;
    const modelPath = path2.join(
      this.packageRoot,
      this.pathRoot,
      this.pathModel,
      this.filename
    );
    let modelData2 = void 0;
    if (this.filename !== "") {
      modelData2 = unlock(
        fs5.readFileSync(
          modelPath,
          "utf8"
        ),
        password,
        modelName
      );
      this.currentModel = modelData2;
      this.trainer.learnedPatterns = new Map(modelData2.learnedPatterns);
      this.trainer.binaryPatterns = new Map(modelData2.binaryPatterns);
      this.trainer.frequentPatterns = new Set(modelData2.frequentPatterns);
      this.trainer.reverseNGrams = modelData2.reverseNGrams;
      const modelNumber = getModelNumber(
        this.filename,
        modelName
      );
      BELAMessage.say({
        type: "success" /* SUCCESS */,
        code: "B3S1" /* SUCCESS_TAKE_ACTION */,
        name: "BELA",
        message: `Successfully loaded model with name _*${modelName}*_ and version _*${modelNumber}*_.`
      });
    } else {
      const similarFile = findSimilarFile(
        path2.join(
          this.packageRoot,
          this.pathModel
        ),
        modelName
      )?.replace(/\-(\d+)\.belamodel/g, "");
      if (similarFile) {
        throw BELAMessage.say({
          type: "error" /* ERROR */,
          code: "B1E4" /* GENERAL_NOT_FOUND */,
          name: "BELA",
          message: `Model with name _*${modelName}*_ not found.`,
          stack: `  \u2022 Found model with name _*${similarFile}*_.
  \u2022 Did you mean _*${similarFile}*_?`
        });
      } else {
        throw BELAMessage.say({
          type: "error" /* ERROR */,
          code: "B1E4" /* GENERAL_NOT_FOUND */,
          name: "BELA",
          message: `Model with name _*${modelName}*_ not found.`,
          stack: `  \u2022 No similar model found.`
        });
      }
    }
    return modelData2 ?? modelData;
  }
  move(modelName1, password1, modelName2, password2) {
    this.filename = getLatestBelamodel(
      path2.join(
        this.packageRoot,
        this.pathModel
      ),
      modelName1
    ) ?? "";
    const modelPath = path2.join(
      this.packageRoot,
      this.pathRoot,
      this.pathModel,
      this.filename
    );
    let modelData2 = void 0;
    if (this.filename !== "") {
      modelData2 = unlock(
        fs5.readFileSync(
          modelPath,
          "utf8"
        ),
        password1,
        modelName1
      );
      const saveFilename = incrementBelamodel(
        path2.join(
          this.packageRoot,
          this.pathModel
        ),
        modelName2,
        modelData2,
        password2
      );
      const saveModelPath = path2.join(
        this.packageRoot,
        this.pathRoot,
        this.pathModel,
        saveFilename
      );
      const modelNumber1 = getModelNumber(this.filename, modelName1);
      const modelNumber2 = getModelNumber(saveFilename, modelName2);
      if (modelName1 === modelName2) {
        (async () => {
          const confirm = await question("Are you sure you want to overwrite the model file with its own data?");
          if (confirm) {
            if (fs5.existsSync(saveModelPath)) {
              BELAMessage.say({
                type: "success" /* SUCCESS */,
                code: "B3S2" /* SUCCESS_ALREADY_EXISTS */,
                name: "BELA",
                message: `Model with name _*${modelName2}*_ and version _*${modelNumber2}*_ already exists.`
              });
              return;
            }
            if (modelData2) fs5.writeFileSync(
              saveModelPath,
              lock(
                modelData2,
                password2,
                modelName2
              ),
              "utf8"
            );
            BELAMessage.say({
              type: "success" /* SUCCESS */,
              code: "B3S1" /* SUCCESS_TAKE_ACTION */,
              name: "BELA",
              message: `Successfully moved model with name _*${modelName1}*_ and version _*${modelNumber1}*_ to a new model with name _*${modelName2}*_ and version _*${modelNumber2}*_.`
            });
          }
        })();
      } else {
        if (fs5.existsSync(saveModelPath)) {
          BELAMessage.say({
            type: "success" /* SUCCESS */,
            code: "B3S2" /* SUCCESS_ALREADY_EXISTS */,
            name: "BELA",
            message: `Model with name _*${modelName2}*_ and version _*${modelNumber2}*_ already exists.`
          });
          return;
        }
        if (modelData2) fs5.writeFileSync(
          saveModelPath,
          lock(
            modelData2,
            password2,
            modelName2
          ),
          "utf8"
        );
        BELAMessage.say({
          type: "success" /* SUCCESS */,
          code: "B3S1" /* SUCCESS_TAKE_ACTION */,
          name: "BELA",
          message: `Successfully moved model with name _*${modelName1}*_ and version _*${modelNumber1}*_ to a new model with name _*${modelName2}*_ and version _*${modelNumber2}*_.`
        });
      }
    }
  }
  read(modelName, password) {
    this.filename = getLatestBelamodel(
      path2.join(
        this.packageRoot,
        this.pathModel
      ),
      modelName
    ) ?? "";
    this.password = password;
    const modelPath = path2.join(
      this.packageRoot,
      this.pathRoot,
      this.pathModel,
      this.filename
    );
    let modelData2 = void 0;
    if (this.filename !== "") {
      modelData2 = unlock(
        fs5.readFileSync(modelPath, "utf8"),
        password,
        modelName
      );
      return modelData2;
    }
    return modelData;
  }
};

// src/image/PatternTrainer.ts
var PatternTrainer2 = class {
  constructor(nGramOrder, learningRate, momentum, layers) {
    this.nGramOrder = nGramOrder;
    this.learningRate = learningRate;
    this.momentum = momentum;
    this.layers = layers;
    this.binaryPatterns = /* @__PURE__ */ new Map();
    this.invalidPatterns = /* @__PURE__ */ new Set();
    this.frequentPatterns = /* @__PURE__ */ new Set();
  }
  nGramPatterns = /* @__PURE__ */ new Map();
  totalNGrams = /* @__PURE__ */ new Map();
  reverseNGrams = {};
  learnedPatterns = /* @__PURE__ */ new Map();
  binaryPatterns;
  invalidPatterns;
  frequentPatterns;
  wordAssociations = /* @__PURE__ */ new Map();
  punctuationStats = /* @__PURE__ */ new Map();
  binaryAttention = /* @__PURE__ */ new Map();
  learnImage(title, imageRGB, vocab, maxSubstringToken) {
    const words = tokenize(
      title,
      vocab,
      maxSubstringToken
    );
    const flatPixels = [];
    for (let y = 0; y < imageRGB.length; y++) {
      for (let x = 0; x < imageRGB[y].length; x++) {
        const [r, g, b] = imageRGB[y][x];
        const colorCode = `${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
        flatPixels.push(colorCode);
      }
    }
    const binaryPixels = flatPixels.map((pix) => wordToBinary(pix));
    for (let i = 0; i < binaryPixels.length - 1; i++) {
      const current = binaryPixels[i];
      const next = binaryPixels[i + 1];
      if (!this.learnedPatterns.has(current)) {
        this.learnedPatterns.set(current, { nextWords: /* @__PURE__ */ new Map(), totalNextWords: 0 });
      }
      const pattern = this.learnedPatterns.get(current);
      const layerFactor = this.layers.length;
      pattern.nextWords.set(next, (pattern.nextWords.get(next) || 0) + this.learningRate * layerFactor);
      pattern.totalNextWords += this.learningRate * layerFactor;
    }
    this.learnContextualPatterns(words);
  }
  learnNGrams(sentence, vocab, maxSubstringToken) {
    const words = tokenize(
      sentence,
      vocab,
      maxSubstringToken
    );
    for (let i = 0; i < words.length; i++) {
      words[i] = wordToBinary(words[i]);
    }
    for (let i = 0; i < words.length - this.nGramOrder; i++) {
      const nGramKey = words.slice(i, i + this.nGramOrder).join(" ");
      const nextWord = words[i + this.nGramOrder];
      if (!this.nGramPatterns.has(nGramKey)) {
        this.nGramPatterns.set(nGramKey, /* @__PURE__ */ new Map());
        this.totalNGrams.set(nGramKey, 0);
      }
      const pattern = this.nGramPatterns.get(nGramKey);
      pattern.set(nextWord, (pattern.get(nextWord) || 0) + 1);
      this.totalNGrams.set(nGramKey, this.totalNGrams.get(nGramKey) + 1);
    }
  }
  learnBinary(inputBinary, outputBinary) {
    if (!this.binaryPatterns.has(inputBinary)) {
      this.binaryPatterns.set(inputBinary, {
        distribution: getDistribution(inputBinary),
        frequency: 1,
        output: outputBinary
      });
    } else {
      const pattern = this.binaryPatterns.get(inputBinary);
      const layerFactor = this.layers.reduce((sum, neurons) => sum + neurons, 0) / this.layers.length;
      const adjustedMomentum = this.momentum * (1 + layerFactor * 1e-3);
      if (pattern.frequency && this.learningRate && this.momentum) {
        pattern.frequency = pattern.frequency + this.learningRate * (1 - adjustedMomentum);
      }
      this.binaryPatterns.set(inputBinary, pattern);
    }
    this.strengthenAssociation(inputBinary, outputBinary, this.learningRate);
    this.addBinaryAttention(inputBinary, outputBinary, this.learningRate);
    if (this.binaryPatterns.get(inputBinary).frequency > 5) {
      this.frequentPatterns.add(inputBinary);
      this.strengthenAssociation(inputBinary, outputBinary, this.learningRate * 2);
    }
  }
  learnTopics(sentences) {
    const topicCandidates = /* @__PURE__ */ new Map();
    for (const sentence of sentences) {
      const words = sentence.toLowerCase().split(" ");
      const n = this.nGramOrder;
      for (let i = 0; i <= words.length - n; i++) {
        const nGramKey = words.slice(i, i + n).join(" ");
        const nextWord = words[i + n];
        const patternMap = this.nGramPatterns.get(nGramKey);
        const total = this.totalNGrams.get(nGramKey) || 0;
        if (patternMap && total > 0) {
          const pattern = this.learnedPatterns.get(nGramKey);
          const totalNextWords = pattern?.totalNextWords ?? 1;
          for (const [word, freq] of patternMap.entries()) {
            const confidence = freq / total;
            const dynamicThreshold = Math.max(0.05, 1 / (1 + totalNextWords));
            if (confidence >= dynamicThreshold) {
              if (!topicCandidates.has(nGramKey)) topicCandidates.set(nGramKey, /* @__PURE__ */ new Set());
              topicCandidates.get(nGramKey).add(word);
            }
          }
        }
      }
    }
    const topics = /* @__PURE__ */ new Map();
    for (const [key, words] of topicCandidates.entries()) {
      if (words.size > 1) {
        topics.set(key, Array.from(words));
      }
    }
    return topics;
  }
  getReverseNGram(sentence) {
    const words = sentence.split(" ");
    for (let i = 0; i < words.length; i++) {
      let prevWord = words[i - 1];
      let currentWord = words[i];
      if (!this.reverseNGrams[currentWord]) {
        this.reverseNGrams[currentWord] = [];
      }
      this.reverseNGrams[currentWord].push(prevWord);
    }
  }
  getMostLikelyWord(candidates) {
    if (!candidates.length) return null;
    let wordCount = {};
    for (let word of candidates) {
      wordCount[word] = (wordCount[word] || 0) + 1;
    }
    let sortedWords = Object.entries(wordCount).sort((a, b) => b[1] - a[1]);
    return sortedWords[0][0];
  }
  getPredictionConfidence(word) {
    const pattern = this.learnedPatterns.get(word);
    if (!pattern) return 0;
    let maxFreq = 0;
    for (let val of pattern.nextWords.values()) {
      if (val > maxFreq) maxFreq = val;
    }
    return maxFreq / pattern.totalNextWords;
  }
  strengthenAssociation(inputBinary, outputBinary, weight = 1) {
    const inputSentence = binaryToWord(inputBinary);
    const outputSentence = binaryToWord(outputBinary);
    const inputSplit = inputSentence.split(" ");
    const outputSplit = outputSentence.split(" ");
    const inputChunks = [];
    const outputChunks = [];
    for (let i = 0; i < inputSplit.length; i++) {
      inputChunks.push(wordToBinary(inputSplit[i]));
    }
    for (let i = 0; i < outputSplit.length; i++) {
      outputChunks.push(wordToBinary(outputSplit[i]));
    }
    for (let i = 0; i < inputChunks.length; i++) {
      for (let j = 0; j < outputChunks.length; j++) {
        if (!this.wordAssociations.has(inputChunks[i])) {
          this.wordAssociations.set(inputChunks[i], /* @__PURE__ */ new Map());
        }
        const assoc = this.wordAssociations.get(inputChunks[i]);
        assoc.set(outputChunks[j], (assoc.get(outputChunks[j]) || 0) + weight);
      }
    }
  }
  learnContextualPatterns(words) {
    const contextWindow = 2;
    for (let i = 0; i < words.length; i++) {
      const wordBinary = wordToBinary(words[i]);
      const context = words.slice(Math.max(0, i - contextWindow), i).concat(words.slice(i + 1, i + 1 + contextWindow)).map(wordToBinary);
      if (!this.wordAssociations.has(wordBinary)) {
        this.wordAssociations.set(wordBinary, /* @__PURE__ */ new Map());
      }
      const map = this.wordAssociations.get(wordBinary);
      for (const ctxBinary of context) {
        map.set(ctxBinary, (map.get(ctxBinary) || 0) + 1);
      }
    }
  }
  addBinaryAttention(inputBinary, outputBinary, weight = 1, decayFactor = 0.95) {
    if (!this.binaryAttention.has(inputBinary)) {
      this.binaryAttention.set(inputBinary, /* @__PURE__ */ new Map());
    }
    const attentionMap = this.binaryAttention.get(inputBinary);
    for (const [key, val] of attentionMap.entries()) {
      attentionMap.set(key, val * decayFactor);
    }
    attentionMap.set(
      outputBinary,
      (attentionMap.get(outputBinary) || 0) + weight
    );
  }
};

// src/index.ts
var BELA = class {
  isModel = false;
  packageRoot = path3.dirname(__require.main?.filename ?? process.cwd());
  /** Conversation */
  conversationTrainer;
  conversationMatching;
  conversationPredictor;
  manager;
  /** Image */
  imageTrainer;
  topicPatterns = /* @__PURE__ */ new Map([
    ["makanan", ["nasi goreng", "mie ayam", "sate"]],
    ["teknologi", ["AI", "robot", "machine learning"]]
  ]);
  vocabs;
  epochs;
  learningRate;
  momentum;
  randomness;
  nGramOrder;
  layers;
  pathRoot;
  pathModel;
  pathBackup;
  autoIncrement;
  autoDelete;
  autoDeleteMax;
  maxTokenLength;
  constructor(config = {}) {
    this.epochs = config.parameter?.epochs ?? 5;
    this.learningRate = config.parameter?.learningRate ?? 0.05;
    this.momentum = config.parameter?.momentum ?? 0.9;
    this.randomness = config.parameter?.randomness ?? 0.05;
    this.nGramOrder = config.parameter?.nGramOrder ?? 3;
    this.layers = config.parameter?.layers ?? [64, 32, 16];
    this.pathRoot = config.path?.root ?? "./";
    this.pathModel = config.path?.model ?? "./";
    this.pathBackup = config.path?.backup ?? "./";
    this.autoIncrement = config?.autoIncrement ?? true;
    this.autoDelete = config?.autoDelete ?? true;
    this.autoDeleteMax = config?.autoDeleteMax ?? 10;
    this.vocabs = [];
    this.maxTokenLength = 5;
    this.conversationTrainer = new PatternTrainer(
      this.nGramOrder,
      this.learningRate,
      this.momentum,
      this.layers
    );
    this.conversationMatching = new PatternMatching(this.conversationTrainer);
    this.conversationPredictor = new PatternPredictor(
      this.conversationTrainer,
      this.conversationMatching,
      this.randomness
    );
    this.manager = new ModelManager(
      this.conversationTrainer,
      this.epochs,
      this.learningRate,
      this.momentum,
      this.randomness,
      this.nGramOrder,
      this.layers,
      this.packageRoot,
      this.pathRoot,
      this.pathModel,
      this.pathBackup
    );
    this.imageTrainer = new PatternTrainer2(
      this.nGramOrder,
      this.learningRate,
      this.momentum,
      this.layers
    );
  }
  train(dataset, vocabs, maxTokenLength) {
    setVocab(vocabs);
    this.vocabs = vocabs;
    this.maxTokenLength = maxTokenLength;
    if (isConversationDataset(dataset)) {
      if (!dataset || dataset.length === 0 || !vocabs || vocabs.length === 0 || typeof maxTokenLength !== "number") {
        throw BELAMessage.say({
          type: "error" /* ERROR */,
          code: "B1E1" /* GENERAL_NOT_FULFILLED */,
          name: "BELA",
          message: `${!dataset || dataset.length === 0 ? "Training dataset cannot be empty." : !vocabs || vocabs.length === 0 ? "Vocab training cannot be empty." : "maxTokenLength must be of type number"}`
        });
      }
      if (this.epochs) {
        for (let epoch = 0; epoch < this.epochs; epoch++) {
          if (!Array.isArray(dataset) || !dataset.every((item) => typeof item === "object" && item !== null)) {
            throw BELAMessage.say({
              type: "error" /* ERROR */,
              code: "B1E1" /* GENERAL_NOT_FULFILLED */,
              name: "BELA",
              message: "Dataset must be of type array of objects."
            });
          }
          try {
            dataset.forEach(({ input, output }) => {
              this.conversationTrainer.learnSentence(input, this.vocabs, maxTokenLength);
              this.conversationTrainer.learnSentence(output, this.vocabs, maxTokenLength);
              this.conversationTrainer.getReverseNGram(input);
              this.conversationTrainer.getReverseNGram(output);
            });
            BELAMessage.say({
              type: "epoch" /* EPOCH */,
              code: epoch + 1,
              name: "BELA",
              message: "is complete."
            });
          } catch (err) {
            throw BELAMessage.say({
              type: "error" /* ERROR */,
              code: "B1E2" /* GENERAL_CORRUPTED_PROBLEM */,
              name: "BELA",
              message: "Corrupted training dataset."
            });
          }
        }
      }
      this.isModel = true;
    } else if (isImageDataset(dataset)) {
      try {
        dataset.forEach(({ title, image }) => {
          this.imageTrainer.learnImage(
            title,
            image,
            this.vocabs,
            this.maxTokenLength
          );
        });
      } catch (err) {
      }
    }
  }
  fineTune(dataset, vocabs, maxTokenLength) {
    if (this.manager.currentModel === modelData) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Model must be loaded before fine-tuning."
      });
    }
    if (!dataset || dataset.length === 0) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Fine-tuning dataset cannot be empty."
      });
    }
    setVocab(vocabs);
    this.maxTokenLength = maxTokenLength;
    if (this.epochs) {
      for (let epoch = 0; epoch < this.epochs; epoch++) {
        if (!Array.isArray(dataset) || !dataset.every((item) => typeof item === "object" && item !== null)) {
          throw BELAMessage.say({
            type: "error" /* ERROR */,
            code: "B1E1" /* GENERAL_NOT_FULFILLED */,
            name: "BELA",
            message: "Dataset must be of type array of objects."
          });
        }
        try {
          dataset.forEach(({ input, output }) => {
            this.conversationTrainer.learnSentence(input, this.vocabs, maxTokenLength);
            this.conversationTrainer.learnSentence(output, this.vocabs, maxTokenLength);
          });
          BELAMessage.say({
            type: "epoch" /* EPOCH */,
            code: epoch + 1,
            name: "BELA",
            message: "is complete."
          });
        } catch (err) {
          throw BELAMessage.say({
            type: "error" /* ERROR */,
            code: "B1E2" /* GENERAL_CORRUPTED_PROBLEM */,
            name: "BELA",
            message: "Corrupted fine-tuning dataset."
          });
        }
      }
    }
    const oldModelData = this.manager.currentModel;
    const newModelData = {
      parameters: {
        epochs: this.epochs,
        learningRate: this.learningRate,
        momentum: this.momentum,
        randomness: this.randomness,
        nGramOrder: this.nGramOrder,
        layers: this.layers
      },
      learnedPatterns: Array.from(this.conversationTrainer.learnedPatterns.entries()),
      binaryPatterns: Array.from(this.conversationTrainer.binaryPatterns.entries()),
      frequentPatterns: Array.from(this.conversationTrainer.frequentPatterns),
      reverseNGrams: this.conversationTrainer.reverseNGrams
    };
    const mergedModelData = {
      parameters: {
        ...oldModelData.parameters,
        ...newModelData.parameters
      },
      learnedPatterns: Array.from(/* @__PURE__ */ new Set([
        ...oldModelData.learnedPatterns,
        ...newModelData.learnedPatterns
      ])),
      binaryPatterns: Array.from(/* @__PURE__ */ new Set([
        ...oldModelData.binaryPatterns,
        ...newModelData.binaryPatterns
      ])),
      frequentPatterns: Array.from(/* @__PURE__ */ new Set([
        ...oldModelData.frequentPatterns,
        ...newModelData.frequentPatterns
      ])),
      reverseNGrams: {
        ...oldModelData.reverseNGrams,
        ...newModelData.reverseNGrams
      }
    };
    this.conversationTrainer.learnedPatterns = new Map(mergedModelData.learnedPatterns);
    this.conversationTrainer.binaryPatterns = new Map(mergedModelData.binaryPatterns);
    this.conversationTrainer.frequentPatterns = new Set(mergedModelData.frequentPatterns);
    this.conversationTrainer.reverseNGrams = mergedModelData.reverseNGrams;
    const saveModelPath = path3.join(
      this.packageRoot,
      this.pathRoot,
      this.pathModel,
      this.manager.filename
    );
    fs6.writeFileSync(saveModelPath, lock(mergedModelData, this.manager.password), "utf8");
  }
  info(options = {}) {
    console.log(options.parameter);
    if (options.parameter && options.parameter === true) {
      return {
        epochs: this.epochs,
        learningRate: this.learningRate,
        momentum: this.momentum,
        randomness: this.randomness,
        nGramOrder: this.nGramOrder,
        layers: this.layers
      };
    } else if (options.training && options.training === true) {
      const nextWordsInfo = [];
      const binaryPatternsInfo = [];
      const frequentlyPatternsInfo = [];
      for (let [word, data] of this.conversationTrainer.learnedPatterns) {
        nextWordsInfo.push({ word: [data.nextWords] });
      }
      for (let [inputBinary, data] of this.conversationTrainer.binaryPatterns) {
        binaryPatternsInfo.push({ input: inputBinary, output: data.output, frekuensi: data.frequency });
      }
      this.conversationTrainer.frequentPatterns.forEach((pattern) => {
        frequentlyPatternsInfo.push({ pattern });
      });
      return {
        nextWordsInfo,
        binaryPatternsInfo,
        frequentlyPatternsInfo
      };
    }
    return {};
  }
  predictText(prompt, options = {
    minLength: 2,
    maxLength: 5,
    maxTest: 3,
    logTest: false
  }) {
    if (typeof prompt !== "string" || typeof options.maxLength !== "number" || typeof options.maxTest !== "number" || typeof options.logTest !== "boolean") {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: `${typeof prompt !== "string" ? "Prompt must be of type string." : typeof options.maxLength !== "number" ? "maxLength must be of type number." : typeof options.maxTest !== "number" ? "maxTest must be of type number." : "logTest must be of type boolean."}`
      });
    }
    if (!this.isModel) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Model has not been trained or loaded."
      });
    }
    if (!prompt) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Prediction prompts cannot be empty."
      });
    }
    let response = [];
    let newResponse = [];
    for (let test = 0; test < options.maxTest; test++) {
      let words = tokenize(
        prompt,
        this.vocabs,
        this.maxTokenLength
      );
      for (let i = 0; i < words.length; i++) {
        words[i] = wordToBinary(words[i]);
      }
      response = this.conversationPredictor.generateSentence(words);
      for (let i = 0; i < response.length; i++) {
        const splitResponse = response[i].split(" ");
        for (let j = 0; j < splitResponse.length; j++) {
          newResponse.push(binaryToWord(splitResponse[j]));
        }
      }
      if (options.logTest) {
        BELAMessage.say({
          type: "test" /* TEST */,
          code: test + 1,
          name: "BELA",
          message: detokenize(newResponse)
        });
      }
    }
    console.log(newResponse);
    return detokenize(newResponse);
  }
  predictImage(prompt, options = {
    width: 16,
    height: 16,
    maxTest: 3,
    logTest: false
  }) {
    if (typeof prompt !== "string" || typeof options.width !== "number" || typeof options.height !== "number" || typeof options.maxTest !== "number" || typeof options.logTest !== "boolean") {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: `${typeof prompt !== "string" ? "Prompt must be of type string." : typeof options.width !== "number" ? "width must be of type number." : typeof options.height !== "number" ? "height must be of typ number." : typeof options.maxTest !== "number" ? "maxTest must be of type number." : "logTest must be of type boolean."}`
      });
    }
    if (!this.isModel) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Model has not been trained or loaded."
      });
    }
    if (!prompt) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "Prediction prompts cannot be empty."
      });
    }
    let response = [];
    for (let test = 0; test < options.maxTest; test++) {
      response = [];
      let words = tokenize(
        prompt,
        this.vocabs,
        this.maxTokenLength
      );
      for (let i = 0; i < words.length; i++) {
        words[i] = wordToBinary(words[i]);
      }
      let lastWord = words[words.length - 1];
      let firstWord = words[0];
      let startWord = this.conversationPredictor.predictNextWord(lastWord);
      if (!startWord || startWord.length <= 1) {
        startWord = this.conversationPredictor.predictPrevWord(firstWord);
      }
      if (startWord) response.push(startWord);
      let topic = null;
      for (let [password, values] of this.topicPatterns.entries()) {
        if (values.some((v) => prompt.includes(v))) {
          topic = password;
          break;
        }
      }
      if (topic) {
        console.log(`Detected topics: ${topic}`);
      }
      for (let i = words.length; i < options.width; i++) {
        let nGrampassword = "";
        if (response && this.nGramOrder) {
          nGrampassword = response.slice(-this.nGramOrder).join(" ");
        }
        let nextWord = this.conversationPredictor.predictNextWord(nGrampassword);
        if (!nextWord) {
          nextWord = this.conversationMatching.findClosestWord(nGrampassword) || this.conversationPredictor.predictNextWord(response[response.length - 1]);
        }
        if (!nextWord) {
          nextWord = this.conversationPredictor.predictPrevWord(response[0]);
        }
        if (!nextWord) break;
        let windowSize = 3;
        let recentWords = response.slice(-windowSize);
        if (recentWords.includes(nextWord)) {
          continue;
        }
        response.push(nextWord);
      }
      for (let i = 0; i < response.length; i++) {
        response[i] = binaryToWord(response[i]);
      }
      if (options.logTest) {
        BELAMessage.say({
          type: "test" /* TEST */,
          code: test + 1,
          name: "BELA",
          message: detokenize(response)
        });
      }
    }
    return detokenize(response);
  }
  save(name, options = {
    password: "",
    metadata
  }) {
    if (!name) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "File or model name cannot be empty."
      });
    }
    if (!options.password) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "password cannot be empty."
      });
    }
    if (this.autoIncrement === false && !name.endsWith(".belamodel")) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "File names do not end in .belamodel."
      });
    }
    if (this.autoDelete) {
      this.manager.save(
        name,
        getFullEnv(options.password),
        this.autoDeleteMax ?? 10,
        true,
        options.metadata
      );
      return;
    }
    this.manager.save(
      name,
      getFullEnv(options.password),
      this.autoDeleteMax ?? 10,
      false,
      options.metadata
    );
  }
  load(name, options = {
    password: ""
  }) {
    if (!name) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "File or model name cannot be empty."
      });
    }
    if (!options.password) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "password cannot be empty."
      });
    }
    if (this.autoIncrement === false && !name.endsWith(".belamodel")) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B1E1" /* GENERAL_NOT_FULFILLED */,
        name: "BELA",
        message: "File names do not end in .belamodel."
      });
    }
    const data = this.manager.load(
      name,
      getFullEnv(options.password)
    );
    if (!data || !data.parameters) {
      throw BELAMessage.say({
        type: "error" /* ERROR */,
        code: "B2E1" /* INTERNAL_NOT_FULFILLED */,
        name: "BELA",
        message: this.autoIncrement ? `Failed to read model data with name ${name}.` : `Failed to read data model from file named ${name}.`
      });
    }
    this.epochs = data.parameters.epochs;
    this.learningRate = data.parameters.learningRate;
    this.momentum = data.parameters.momentum;
    this.randomness = data.parameters.randomness;
    this.nGramOrder = data.parameters.nGramOrder;
    this.layers = data.parameters.layers;
    this.isModel = true;
  }
  move(from, fromOptions = {
    password: ""
  }, to, toOptions = {
    password: ""
  }) {
    this.manager.move(
      from,
      fromOptions.password,
      to,
      toOptions.password
    );
  }
  read(name, options = {
    password: ""
  }) {
    return this.manager.read(
      name,
      options.password
    );
  }
  vocab(data, vocabSize = 50) {
    const tokenFreq = /* @__PURE__ */ new Map();
    const wordList = [];
    if (isConversationDataset(data)) {
      for (const pair of data) {
        const combinedText = `\u2581${pair.input} \u2581${pair.output}`.toLowerCase();
        const words = combinedText.split(/\s+/);
        for (const word of words) {
          const chars = word.split("");
          chars.unshift("\u2581");
          wordList.push(chars);
        }
      }
    } else if (isImageDataset(data)) {
      for (const pair of data) {
        const combinedText = `\u2581${pair.title}`.toLowerCase();
        const words = combinedText.split(/\s+/);
        for (const word of words) {
          const chars = word.split("");
          chars.unshift("\u2581");
          wordList.push(chars);
        }
      }
    }
    for (const word of wordList) {
      for (let i = 0; i < word.length - 1; i++) {
        const pair = `${word[i]} ${word[i + 1]}`;
        tokenFreq.set(pair, (tokenFreq.get(pair) || 0) + 1);
      }
    }
    const vocabSet = /* @__PURE__ */ new Set();
    wordList.forEach((w) => w.forEach((ch) => vocabSet.add(ch)));
    while (vocabSet.size < vocabSize && tokenFreq.size > 0) {
      const [bestPair] = [...tokenFreq.entries()].sort((a2, b2) => b2[1] - a2[1])[0];
      const [a, b] = bestPair.split(" ");
      const merged = a + b;
      vocabSet.add(merged);
      for (let w = 0; w < wordList.length; w++) {
        const word = wordList[w];
        const newWord = [];
        let i = 0;
        while (i < word.length) {
          if (i < word.length - 1 && word[i] === a && word[i + 1] === b) {
            newWord.push(merged);
            i += 2;
          } else {
            newWord.push(word[i]);
            i++;
          }
        }
        wordList[w] = newWord;
      }
      tokenFreq.clear();
      for (const word of wordList) {
        for (let i = 0; i < word.length - 1; i++) {
          const pair = `${word[i]} ${word[i + 1]}`;
          tokenFreq.set(pair, (tokenFreq.get(pair) || 0) + 1);
        }
      }
    }
    return ["<unk>", ...Array.from(vocabSet)];
  }
};
export {
  BELA
};
