require("dotenv").config();
const { _isArray } = require("../utils/utils.js");

const settings = {
  TIME_SLEEP: process.env.TIME_SLEEP ? parseInt(process.env.TIME_SLEEP) : 8,
  MAX_THEADS: process.env.MAX_THEADS ? parseInt(process.env.MAX_THEADS) : 10,
  MAX_LEVEL_SPEED: process.env.MAX_LEVEL_SPEED ? parseInt(process.env.MAX_LEVEL_SPEED) : 10,
  MAX_THEADS_NO_PROXY: process.env.MAX_THEADS_NO_PROXY ? parseInt(process.env.MAX_THEADS_NO_PROXY) : 10,
  AMOUNT_REF: process.env.AMOUNT_REF ? parseInt(process.env.AMOUNT_REF) : 100,
  AMOUNT_REF_CODE: process.env.AMOUNT_REF_CODE ? parseInt(process.env.AMOUNT_REF_CODE) : 1,

  SKIP_TASKS: process.env.SKIP_TASKS ? JSON.parse(process.env.SKIP_TASKS.replace(/'/g, '"')) : [],
  TYPE_HERO_UPGRADE: process.env.TYPE_HERO_UPGRADE ? JSON.parse(process.env.TYPE_HERO_UPGRADE.replace(/'/g, '"')) : [],
  TYPE_HERO_RESET: process.env.TYPE_HERO_RESET ? JSON.parse(process.env.TYPE_HERO_RESET.replace(/'/g, '"')) : [],
  CODE_GATEWAY: process.env.CODE_GATEWAY ? JSON.parse(process.env.CODE_GATEWAY.replace(/'/g, '"')) : [],
  DAILY_COMBO: process.env.DAILY_COMBO ? JSON.parse(process.env.DAILY_COMBO.replace(/'/g, '"')) : [],
  TASKS_ID: process.env.TASKS_ID ? JSON.parse(process.env.TASKS_ID.replace(/'/g, '"')) : [],

  AUTO_TASK: process.env.AUTO_TASK ? process.env.AUTO_TASK.toLowerCase() === "true" : false,
  AUTO_CHECKIN: process.env.AUTO_CHECKIN ? process.env.AUTO_CHECKIN.toLowerCase() === "true" : false,
  AUTO_CREATE_REF_CODE: process.env.AUTO_CREATE_REF_CODE ? process.env.AUTO_CREATE_REF_CODE.toLowerCase() === "true" : false,

  AUTO_SHOW_COUNT_DOWN_TIME_SLEEP: process.env.AUTO_SHOW_COUNT_DOWN_TIME_SLEEP ? process.env.AUTO_SHOW_COUNT_DOWN_TIME_SLEEP.toLowerCase() === "true" : false,
  AUTO_CLAIM_BONUS: process.env.AUTO_CLAIM_BONUS ? process.env.AUTO_CLAIM_BONUS.toLowerCase() === "true" : false,
  ENABLE_ADVANCED_MERGE: process.env.ENABLE_ADVANCED_MERGE ? process.env.ENABLE_ADVANCED_MERGE.toLowerCase() === "true" : false,
  ENABLE_DEBUG: process.env.ENABLE_DEBUG ? process.env.ENABLE_DEBUG.toLowerCase() === "true" : false,

  AUTO_UPGRADE_SPEED: process.env.AUTO_UPGRADE_SPEED ? process.env.AUTO_UPGRADE_SPEED.toLowerCase() === "true" : false,
  AUTO_BUY_PET: process.env.AUTO_BUY_PET ? process.env.AUTO_BUY_PET.toLowerCase() === "true" : false,
  AUTO_SELL_PET: process.env.AUTO_SELL_PET ? process.env.AUTO_SELL_PET.toLowerCase() === "true" : false,

  CONNECT_WALLET: process.env.CONNECT_WALLET ? process.env.CONNECT_WALLET.toLowerCase() === "true" : false,

  ADVANCED_ANTI_DETECTION: process.env.ADVANCED_ANTI_DETECTION ? process.env.ADVANCED_ANTI_DETECTION.toLowerCase() === "true" : false,
  AUTO_CODE_GATEWAY: process.env.AUTO_CODE_GATEWAY ? process.env.AUTO_CODE_GATEWAY.toLowerCase() === "true" : false,
  USE_PROXY: process.env.USE_PROXY ? process.env.USE_PROXY.toLowerCase() === "true" : false,

  API_KEY: process.env.API_KEY ? process.env.API_KEY : null,
  BASE_URL: process.env.BASE_URL ? process.env.BASE_URL : null,
  BASE_URL_V2: process.env.BASE_URL_V2 ? process.env.BASE_URL_V2 : null,

  REF_CODE: process.env.REF_CODE ? process.env.REF_CODE : "ZNRHXLAG",

  TYPE_CAPTCHA: process.env.TYPE_CAPTCHA ? process.env.TYPE_CAPTCHA : null,
  API_KEY_2CAPTCHA: process.env.API_KEY_2CAPTCHA ? process.env.API_KEY_2CAPTCHA : null,
  API_KEY_CAPMONSTER: process.env.API_KEY_CAPMONSTER ? process.env.API_KEY_CAPMONSTER : null,
  API_KEY_CAPSOLVER: process.env.API_KEY_CAPSOLVER ? process.env.API_KEY_CAPSOLVER : null,

  API_KEY_ANTI_CAPTCHA: process.env.API_KEY_ANTI_CAPTCHA ? process.env.API_KEY_ANTI_CAPTCHA : null,
  CAPTCHA_URL: process.env.CAPTCHA_URL ? process.env.CAPTCHA_URL : null,
  WEBSITE_KEY: process.env.WEBSITE_KEY ? process.env.WEBSITE_KEY : null,

  DELAY_BETWEEN_REQUESTS: process.env.DELAY_BETWEEN_REQUESTS && _isArray(process.env.DELAY_BETWEEN_REQUESTS) ? JSON.parse(process.env.DELAY_BETWEEN_REQUESTS) : [1, 5],
  DELAY_START_BOT: process.env.DELAY_START_BOT && _isArray(process.env.DELAY_START_BOT) ? JSON.parse(process.env.DELAY_START_BOT) : [1, 15],
  DELAY_CHAT: process.env.DELAY_CHAT && _isArray(process.env.DELAY_CHAT) ? JSON.parse(process.env.DELAY_CHAT) : [1, 15],
  AMOUNT_CHAT: process.env.AMOUNT_CHAT && _isArray(process.env.AMOUNT_CHAT) ? JSON.parse(process.env.AMOUNT_CHAT) : [5, 10],
};

module.exports = settings;
