const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement, generateId } = require("./utils/utils.js");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");
const { checkBaseUrl } = require("./utils/checkAPI.js");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const ethers = require("ethers");
const { solveCaptcha } = require("./utils/captcha.js");
const questions = loadData("questions.txt");
const nacl = require("tweetnacl");
const Base58 = require("bs58").default;
const conversationHistory = require("./conversationHistory.json");

class ClientAPI {
  constructor(itemData, accountIndex, proxy, baseURL) {
    this.headers = headers;
    this.baseURL = baseURL;
    this.baseURL_v2 = settings.BASE_URL_V2;
    this.localItem = null;
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.localStorage = localStorage;
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_random_user_agent() {
    const randomIndex = Math.floor(Math.random() * user_agents.length);
    return user_agents[randomIndex];
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }

    console.log(`[Tài khoản ${this.accountIndex + 1}] Tạo user agent...`.blue);
    const newUserAgent = this.#get_random_user_agent();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[BitQuant][${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 2,
      isAuth: false,
      extraHeaders: {},
      refreshToken: null,
    }
  ) {
    const { retries, isAuth, extraHeaders, refreshToken } = options;

    const headers = {
      ...this.headers,
      ...extraHeaders,
    };

    if (!isAuth && this.token) {
      headers["authorization"] = `Bearer ${this.token}`;
    }

    let proxyAgent = null;
    if (settings.USE_PROXY) {
      proxyAgent = new HttpsProxyAgent(this.proxy);
    }
    let currRetries = 0,
      errorMessage = null,
      errorStatus = 0;

    do {
      try {
        const response = await axios({
          method,
          url,
          headers,
          timeout: 120000,
          ...(proxyAgent ? { httpsAgent: proxyAgent, httpAgent: proxyAgent } : {}),
          ...(method.toLowerCase() != "get" ? { data } : {}),
        });
        if (response?.data?.data) return { status: response.status, success: true, data: response.data.data, error: null };
        return { success: true, data: response.data, status: response.status, error: null };
      } catch (error) {
        errorStatus = error.status;
        errorMessage = error?.response?.data?.message ? error?.response?.data : error.message;
        this.log(`Request failed: ${url} | Status: ${error.status} | ${JSON.stringify(errorMessage || {})}...`, "warning");

        if (error.message.includes("stream has been aborted")) {
          return { success: false, status: error.status, data: null, error: error.response.data.error || error.response.data.message || error.message };
        }

        // if (error.status == 401) {
        //   this.log(`Unauthorized: ${url} | trying get new token...`, "warning");
        //   const token = await this.getValidToken(true);
        //   if (token) {
        //     process.exit(0);
        //   }
        //   this.token = token;
        //   return await this.makeRequest(url, method, data, options);
        // }
        if (error.status == 400) {
          this.log(`Invalid request for ${url}, maybe have new update from server | contact: https://t.me/airdrophuntersieutoc to get new update!`, "error");
          return { success: false, status: error.status, error: errorMessage, data: null };
        }
        if (error.status == 429) {
          this.log(`Rate limit ${JSON.stringify(errorMessage)}, waiting 60s to retries`, "warning");
          await sleep(60);
        }
        if (currRetries > retries) {
          return { status: error.status, success: false, error: errorMessage, data: null };
        }
        currRetries++;
        await sleep(5);
      }
    } while (currRetries <= retries);
    return { status: errorStatus, success: false, error: errorMessage, data: null };
  }

  getCookieData(setCookie) {
    try {
      if (!(setCookie?.length > 0)) return null;
      let cookie = [];
      const item = JSON.stringify(setCookie);
      // const item =
      const nonceMatch = item.match(/user=([^;]+)/);
      if (nonceMatch && nonceMatch[0]) {
        cookie.push(nonceMatch[0]);
      }

      const data = cookie.join(";");
      return cookie.length > 0 ? data : null;
    } catch (error) {
      this.log(`Error get cookie: ${error.message}`, "error");
      return null;
    }
  }

  signMessage(message, secretKey) {
    try {
      const encodedMessage = new TextEncoder().encode(message);
      const decodedSecretKey = Base58.decode(secretKey);
      if (!decodedSecretKey || decodedSecretKey.length !== 64) {
        throw new Error("Invalid private key length");
      }
      const signature = nacl.sign.detached(encodedMessage, decodedSecretKey);

      return Base58.encode(signature);
    } catch (error) {
      throw error;
    }
  }

  async auth() {
    const res = await this.getToken();
    if (!res?.success) {
      this.log(`Get token failed: ${JSON.stringify(res)}`, "error");
      return { success: false, data: null };
    }
    const { token } = res.data;
    const payload = { token: token, returnSecureToken: true };
    return this.makeRequest(`${this.baseURL_v2}/v1/accounts:signInWithCustomToken?key=${settings.API_KEY}`, "post", payload, {
      isAuth: true,
      extraHeaders: {
        "x-client-version": "Chrome/JsCore/11.6.0/FirebaseCore-web",
        "x-firebase-gmpid": "1:976084784386:web:bb57c2b7c2642ce85b1e1b",
      },
    });
  }

  async getToken() {
    const nonce = Date.now();
    const issuedAt = new Date().toISOString();
    const message = `bitquant.io wants you to sign in with your **blockchain** account:\n${this.itemData.address}\n\nURI: https://bitquant.io\nVersion: 1\nChain ID: solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\nNonce: ${nonce}\nIssued At: ${issuedAt}`;
    const signedMessage = this.signMessage(message, this.itemData.privateKey);

    const payload = {
      message: message,
      address: this.itemData.address,
      signature: signedMessage,
    };
    return this.makeRequest(`${this.baseURL}/api/verify/solana`, "post", payload, {
      isAuth: true,
      extraHeaders: {
        "x-client-version": "Chrome/JsCore/11.6.0/FirebaseCore-web",
        "x-firebase-gmpid": "1:976084784386:web:bb57c2b7c2642ce85b1e1b",
      },
    });
  }

  async getUserData() {
    return this.makeRequest(
      `${this.baseURL_v2}/v1/accounts:lookup?key=${settings.API_KEY}`,
      "post",
      { idToken: this.token },
      {
        extraHeaders: {
          "x-client-version": "Chrome/JsCore/11.6.0/FirebaseCore-web",
          "x-firebase-gmpid": "1:976084784386:web:bb57c2b7c2642ce85b1e1b",
        },
      }
    );
  }

  // async refreshToken() {
  //   return this.makeRequest(
  //     `${this.baseURL_v2}/v1/token?key=${settings.API_KEY}`,
  //     "post",
  //     { idToken: this.token },
  //     {
  //       extraHeaders: {
  //         "x-client-version": "Chrome/JsCore/11.6.0/FirebaseCore-web",
  //         "x-firebase-gmpid": "1:976084784386:web:bb57c2b7c2642ce85b1e1b",
  //       },
  //     }
  //   );
  // }

  async verifyCaptcha() {
    const captchaToken = await solveCaptcha();
    if (!captchaToken) {
      this.log(`Can't solve captcha, skipping...`, "warning");
      await sleep(1);
      process.exit(0);
    }
    return this.makeRequest(`${this.baseURL}/api/cloudflare/turnstile/v0/siteverify`, "post", {
      token: captchaToken,
    });
  }

  async checkWhiteList() {
    return this.makeRequest(`${this.baseURL}/api/whitelisted?address=${this.itemData.address}`, "get");
  }

  async getActiveStatus() {
    return this.makeRequest(`${this.baseURL}/api/activity/stats?address=${this.itemData.address}`, "get");
  }

  async sendMess(payload) {
    return this.makeRequest(`${this.baseURL}/api/agent/run`, "post", payload);
  }

  async suggestions(payload) {
    return this.makeRequest(`${this.baseURL}/api/agent/suggestions`, "post", payload);
  }

  async activeCode(reffCode = settings.REF_CODE) {
    return this.makeRequest(`${this.baseURL}/api/invite/use`, "post", {
      code: reffCode,
      address: this.itemData.address,
    });
  }

  async createCode() {
    return this.makeRequest(`${this.baseURL}/api/invite/generate`, "post", {
      address: this.itemData.address,
    });
  }

  async getValidToken(isNew = false) {
    const existingToken = this.token;
    const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);

    this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);
    if (existingToken && !isNew && !isExp) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, trying get new token...", "warning");
    const loginRes = await this.auth();
    if (!loginRes.success) {
      this.log(`Auth failed: ${JSON.stringify(loginRes)}`, "error");
      return null;
    }
    const newToken = loginRes.data;
    if (newToken?.idToken) {
      await saveJson(this.session_name, JSON.stringify(newToken), "localStorage.json");
      this.localItem = newToken;
      return newToken.idToken;
    }
    this.log("Can't get new token...", "warning");
    return null;
  }

  getRandomConversation(conversations) {
    const minLength = 4;
    const maxLength = 16;
    const randomLength = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;

    // Ensure the array has enough elements
    if (conversations.length < randomLength) {
      return conversations;
    }

    const startIndex = Math.floor(Math.random() * (conversations.length - randomLength + 1));

    return conversations.slice(startIndex, startIndex + randomLength);
  }

  async handleMess(userData) {
    const resGet = await this.getActiveStatus();
    let limit = 20;
    let total = 20;

    if (resGet.success) {
      const { daily_message_limit, daily_message_count, points } = resGet.data;
      if (daily_message_limit == daily_message_count) return;
      limit = daily_message_limit - daily_message_count;
      total = daily_message_limit;
    }
    const history = this.getRandomConversation(conversationHistory);
    while (limit > 0) {
      const mess = getRandomElement(questions);
      const payload = {
        context: {
          conversationHistory: history,
          address: this.itemData.address,
          poolPositions: [],
          availablePools: [],
        },
        message: {
          type: "user",
          message: mess,
        },
      };
      this.log(`[${limit}/${total}] Sending mess: ${mess}`);
      const res = await this.sendMess(payload);
      if (res.success) {
        this.log(`[${limit}/${total}] Sent ${mess} success!`, "success");
        await this.suggestions(payload);
      } else {
        this.log(`[${limit}/${total}] Sent message ${mess} failed | ${JSON.stringify(res)}`, "warning");
      }
      if (limit > 1) {
        const timeSleep = getRandomNumber(settings.DELAY_CHAT[0], settings.DELAY_CHAT[1]);
        this.log(`Sleeping for ${timeSleep} seconds to next message...`, "info");
        await sleep(timeSleep);
      }
      limit--;
    }
  }

  async handleSyncData() {
    this.log(`Sync data...`);
    let userData = { success: false, data: null, status: 0 },
      retries = 0;

    do {
      userData = await this.checkWhiteList();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);
    const blance = await this.getActiveStatus();
    if (userData?.data?.allowed !== true) {
      this.log(`Your address ${this.itemData.address} is not whitelisted, skipping...`, "warning");
      return { success: false, data: null, status: 403 };
    }
    if (userData?.success) {
      const { successful_invites, points } = blance.data;
      this.log(`Successful invites: ${successful_invites} | Total points: ${points}`, "custom");
    } else {
      this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.localItem = JSON.parse(this.localStorage[this.session_name] || "{}");
    this.token = this.localItem?.idToken;
    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
      const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
      console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP} | Bắt đầu sau ${timesleep} giây...`.green);
      await sleep(timesleep);
    }

    const token = await this.getValidToken();
    if (!token) return;
    this.token = token;
    const userData = await this.handleSyncData();
    if (userData.success) {
      await sleep(1);
      await this.handleMess(userData.data);
    } else {
      return this.log("Can't get use info...skipping", "error");
    }
  }
}

async function runWorker(workerData) {
  const { itemData, accountIndex, proxy, hasIDAPI } = workerData;
  const to = new ClientAPI(itemData, accountIndex, proxy, hasIDAPI);
  try {
    await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
    parentPort.postMessage({
      accountIndex,
    });
  } catch (error) {
    parentPort.postMessage({ accountIndex, error: error.message });
  } finally {
    if (!isMainThread) {
      parentPort.postMessage("taskComplete");
    }
  }
}

async function main() {
  console.clear();
  showBanner();
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const resCheck = await checkBaseUrl();
  if (!resCheck.endpoint) return console.log(`Không thể tìm thấy ID API, có thể lỗi kết nỗi, thử lại sau!`.red);
  console.log(`${resCheck.message}`.yellow);

  const data = privateKeys.map((val, index) => {
    if (!/^[A-Za-z0-9]+$/.test(val)) {
      console.log(`Invalid private key format | xxx${val.slice(-6)}`.red);
      return null;
    }
    const decodedKey = Base58.decode(val);
    if (!decodedKey || decodedKey.length !== 64) {
      console.log(`Invalid private key length | xxx${val.slice(-6)}`.red);
      return null;
    }
    const keypair = nacl.sign.keyPair.fromSecretKey(decodedKey);
    const address = Base58.encode(keypair.publicKey);
    const proxy = proxies[index % proxies.length] || null; // Ensure proxy is valid or fallback to null
    const item = {
      address: address,
      privateKey: val,
    };
    new ClientAPI(item, index, proxy, resCheck.endpoint, {}).createUserAgent();
    return item;
  });
  await sleep(1);
  while (true) {
    let currentIndex = 0;
    const errors = [];
    while (currentIndex < data.length) {
      const workerPromises = [];
      const batchSize = Math.min(maxThreads, data.length - currentIndex);
      for (let i = 0; i < batchSize; i++) {
        const worker = new Worker(__filename, {
          workerData: {
            hasIDAPI: resCheck.endpoint,
            itemData: data[currentIndex],
            accountIndex: currentIndex,
            proxy: proxies[currentIndex % proxies.length],
          },
        });

        workerPromises.push(
          new Promise((resolve) => {
            worker.on("message", (message) => {
              if (message === "taskComplete") {
                worker.terminate();
              }
              if (settings.ENABLE_DEBUG) {
                console.log(message);
              }
              resolve();
            });
            worker.on("error", (error) => {
              console.log(`Lỗi worker cho tài khoản ${currentIndex}: ${error?.message}`);
              worker.terminate();
              resolve();
            });
            worker.on("exit", (code) => {
              worker.terminate();
              if (code !== 0) {
                errors.push(`Worker cho tài khoản ${currentIndex} thoát với mã: ${code}`);
              }
              resolve();
            });
          })
        );

        currentIndex++;
      }

      await Promise.all(workerPromises);

      if (errors.length > 0) {
        errors.length = 0;
      }

      if (currentIndex < data.length) {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }

    await sleep(3);
    console.log(`=============${new Date().toLocaleString()} | Hoàn thành tất cả tài khoản | Chờ ${settings.TIME_SLEEP} phút=============`.magenta);
    showBanner();
    await sleep(settings.TIME_SLEEP * 60);
  }
}

if (isMainThread) {
  main().catch((error) => {
    console.log("Lỗi rồi:", error);
    process.exit(1);
  });
} else {
  runWorker(workerData);
}
