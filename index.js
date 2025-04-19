import axios from 'axios';
import fs from 'fs/promises';
import readline from 'readline';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { ethers } from 'ethers';
import chalk from 'chalk';
import cfonts from 'cfonts';
import ora from 'ora';

const BNB_RPC_URL = 'https://bsc-dataseed.binance.org/';
const provider = new ethers.JsonRpcProvider(BNB_RPC_URL);
const contractAbi = [
  "function checkIn()",
  "function owner_2(uint16) view returns (uint16)",
  "function blacklist(address) view returns (bool)",
  "function isCheckInEnabled() view returns (bool)",
  "event CheckIn(address indexed user, uint32 day, uint8 consecutiveDays, uint16 pointsEarned, uint32 totalPoints)"
];

function delay(seconds) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

function centerText(text, color = 'yellowBright') {
  const terminalWidth = process.stdout.columns || 80;
  const textLength = text.length;
  const padding = Math.max(0, Math.floor((terminalWidth - textLength) / 2));
  return ' '.repeat(padding) + chalk[color](text);
}

function shorten(str, frontLen = 6, backLen = 4) {
  if (!str || str.length <= frontLen + backLen) return str;
  return `${str.slice(0, frontLen)}....${str.slice(-backLen)}`;
}

async function readPrivateKeys() {
  try {
    const data = await fs.readFile('pk.txt', 'utf-8');
    return data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
  } catch (error) {
    console.error(chalk.red(`Error membaca pk.txt: ${error.message}`));
    return [];
  }
}

async function readProxies() {
  try {
    const data = await fs.readFile('proxy.txt', 'utf-8');
    const proxies = data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    if (proxies.length === 0) {
      console.log(chalk.yellow('File proxy.txt kosong. Melanjutkan tanpa proxy.'));
    }
    return proxies;
  } catch (error) {
    console.log(chalk.yellow('File proxy.txt tidak ditemukan. Melanjutkan tanpa proxy.'));
    return [];
  }
}

function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

function getHeaders(authorization = '', referer = 'https://bytenova.ai/profile', cookie = '') {
  return {
    'accept': 'application/json, text/plain, */*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'cache-control': 'no-cache',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://bytenova.ai',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': referer,
    'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Opera";v="117"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    ...(authorization && { 'authorization': authorization }), 
    ...(cookie && { 'cookie': cookie })
  };
}

function getProxyAgent(proxy) {
  if (!proxy) return undefined;
  if (proxy.startsWith('http://') || proxy.startsWith('https://')) {
    return new HttpsProxyAgent(proxy);
  } else if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
    return new SocksProxyAgent(proxy);
  } else {
    console.log(chalk.yellow(`Tipe proxy tidak dikenal: ${proxy}.`));
    return new HttpsProxyAgent(proxy);
  }
}

function formatKey(key) {
  const formatted = key.replace(/_/g, ' ');
  return formatted.charAt(0).toUpperCase() + formatted.slice(1).toLowerCase();
}

async function getPublicIP(proxy) {
  try {
    const config = proxy ? { httpsAgent: proxy.startsWith('http') ? new HttpsProxyAgent(proxy) : new SocksProxyAgent(proxy) } : {};
    const response = await axios.get('https://api.ipify.org?format=json', config);
    return response.data.ip;
  } catch (error) {
    return 'Error getting IP';
  }
}

async function login(wallet, proxy) {
  const spinner = ora(' Login Process...').start();
  try {
    const address = wallet.address;
    const message = "You hereby confirm that you are the owner of this connected wallet. This is a safe and gasless transaction to verify your ownership. Signing this message will not give ByteNova permission to make transactions with your wallet.";
    const signature = await wallet.signMessage(message);

    const payload = new URLSearchParams();
    payload.append('wallet_signature', signature);
    payload.append('wallet', address);
    payload.append('chain_type', 'BNB');

    const response = await axios.post(
      'https://bytenova.ai/api/wallet_login',
      payload,
      {
        headers: getHeaders(),
        httpsAgent: getProxyAgent(proxy)
      }
    );
    const data = response.data;
    if (data.code !== 0) {
      throw new Error(`Login Failed: ${data.message}`);
    }
    const accessToken = data.data.access_token;
    const setCookies = response.headers['set-cookie'] || [];
    const userCookie = setCookies
      .map(c => c.split(';')[0])
      .find(c => c.startsWith('user='));

    spinner.succeed(chalk.greenBright(' Login Succesfully'));
    return { token: accessToken, wallet: address, cookie: userCookie };
  } catch (error) {
    spinner.fail(chalk.redBright(` Login Error: ${error.message}`));
    return null;
  }
}

async function loginRefresh(token, wallet, cookie, proxy) {
  const spinner = ora(' Refreshing Login...').start();
  try {
    const payload = new URLSearchParams();
    payload.append('wallet', wallet);
    const headers = getHeaders(token, 'https://bytenova.ai/profile');
    if (cookie) headers.cookie = cookie;

    const response = await axios.post(
      'https://bytenova.ai/api/login_refresh',
      payload,
      {
        headers,
        httpsAgent: getProxyAgent(proxy)
      }
    );
    const data = response.data;
    if (data.code !== 0) {
      throw new Error(`Refresh login failed: ${data.message}`);
    }

    spinner.succeed(chalk.greenBright(' Refreshed Successfully'));
    return data.data;
  } catch (error) {
    spinner.fail(chalk.redBright(` Refresh Login Error: ${error.message}`));
    return null;
  }
}

async function getTaskList(token, cookie, proxy) {
  const spinner = ora(' Getting Task List...').start();
  try {
    const response = await axios.get('https://bytenova.ai/api/tweet_list', {
      headers: getHeaders(token, 'https://bytenova.ai/rewards', cookie),
      httpsAgent: getProxyAgent(proxy)
    });
    const data = response.data;
    if (data.code !== 0) {
      throw new Error(` Failed Getting Task List: ${data.message}`);
    }
    spinner.succeed(chalk.greenBright(' Task List Received'));
    return data.data.tweets;
  } catch (error) {
    spinner.fail(chalk.redBright(` Error Getting Task List: ${error.message}`));
    return null;
  }
}

async function completeTask(token, taskId, wallet, text, cookie, proxy) {
  const spinner = ora(` Completing Task: ${text}...`).start();
  try {
    const payload = new URLSearchParams();
    payload.append('task_id', taskId);
    payload.append('wallet', wallet);
    const response = await axios.post('https://bytenova.ai/api/tweet_refresh', payload, {
      headers: getHeaders(token, 'https://bytenova.ai/rewards', cookie),
      httpsAgent: getProxyAgent(proxy)
    });
    const data = response.data;
    if (data.code !== 0) {
      throw new Error(` Failed Completing Task: ${data.message}`);
    }
    spinner.succeed(chalk.greenBright(` Task Completed: ${text}`));
    return true;
  } catch (error) {
    spinner.fail(chalk.redBright(` Error Completing Task: ${text} - ${error.message}`));
    return false;
  }
}

async function performCheckIn(wallet, contract, token, cookie, proxy) {
  const spinner = ora('Checking Check-In Eligibility...').start();
  try {
    const isCheckInEnabled = await contract.isCheckInEnabled();
    if (!isCheckInEnabled) {
      spinner.fail(chalk.red(' Check-in disabled'));
      return;
    }
    const isBlacklisted = await contract.blacklist(wallet.address);
    if (isBlacklisted) {
      spinner.fail(chalk.red(' User is blacklisted'));
      return;
    }

    spinner.start(' Performing check-in...');
    const tx = await contract.checkIn({ gasLimit: 300000 });
    spinner.start(' Waiting for transaction confirmation...');
    const receipt = await tx.wait();
    spinner.succeed(chalk.green(' Check-in successfully'));
    const eventTopic = '0x9c36edb016f6b2d3e83d75ef67b981013ce380f9a3283edac4f7fb0c7474862';
    let checkInData = null;
    for (const log of receipt.logs) {
      if (log.topics[0] === eventTopic) {
        const iface = new ethers.Interface(contractAbi);
        const parsedLog = iface.parseLog(log);
        checkInData = parsedLog.args;
        break;
      }
    }

    if (!checkInData) {
      spinner.fail(chalk.red(' No check-in data found'));
      return;
    }

    const { user, day, consecutiveDays, pointsEarned, totalPoints } = checkInData;

    const payload = new URLSearchParams();
    payload.append('wallet', wallet.address);
    payload.append('network', 'bnb');
    payload.append('hash', receipt.transactionHash);
    payload.append('liners', consecutiveDays.toString());
    payload.append('score', pointsEarned.toString());
    payload.append('today', day.toString());

    const apiResponse = await axios.post('https://bytenova.ai/api/checkin_detail', payload, {
      headers: getHeaders(token, 'https://bytenova.ai', cookie),
      httpsAgent: getProxyAgent(proxy)
    });
    const data = apiResponse.data;
    if (data.code === 0) {
      console.log(chalk.greenBright(' Succesffuly Sent Data To API'));
    } else {
      console.log(chalk.red(` Failed Sent Data To API: ${data.message}`));
    }
  } catch (error) {
    let errorMessage = error.message;
    if (error.reason) {
      errorMessage = error.reason;
    } else if (error.message.includes('Check-in disabled')) {
      errorMessage = 'Check-in disabled';
    } else if (error.message.includes('Is blacklist')) {
      errorMessage = 'User is blacklisted';
    } else if (error.message.includes('Already checked')) {
      errorMessage = ' Already Check-In Today';
      spinner.succeed(chalk.yellow(errorMessage));
      return;
    } else if (error.code === 'BAD_DATA') {
      errorMessage = 'Failed to decode contract data: ABI mismatch';
    } else if (error.code === 'CALL_EXCEPTION') {
      errorMessage = ' Already Check-In Today';
      spinner.succeed(chalk.yellow(errorMessage));
      return;
    }
    spinner.fail(chalk.red(`Check-in error: ${errorMessage}`));
  }
}

async function getCredits(token, wallet, cookie, proxy) {
  const spinner = ora(' Getting Credits...').start();
  try {
    const payload = new URLSearchParams();
    payload.append('wallet', wallet);
    const headers = getHeaders(token, 'https://bytenova.ai/rewards', cookie);
    const response = await axios.post('https://bytenova.ai/api/credit_refresh', payload, {
      headers,
      httpsAgent: getProxyAgent(proxy)
    });

    const data = response.data;
    if (data.code !== 0) {
      throw new Error(`Failed Getting Credits: ${data.message}`);
    }

    spinner.succeed(chalk.greenBright(' Credits Info Received'));
    return data.data;
  } catch (error) {
    spinner.fail(chalk.redBright(` Error Getting Credits: ${error.message}`));
    return null;
  }
}


async function processAccount(privateKey, proxy) {
  try {
    const wallet = new ethers.Wallet(privateKey, provider);
    const loginResult = await login(wallet, proxy);
    if (!loginResult) return;
    const { token, wallet: address, cookie } = loginResult;
    const userInfo = await loginRefresh(token, address, cookie, proxy);
    if (!userInfo) return;
    console.log();
    console.log(chalk.bold.whiteBright(`Username          : ${userInfo.twitter_name}`));
    console.log(chalk.bold.whiteBright(`Wallet            : ${userInfo.display_name}`));
    const ip = await getPublicIP(proxy); 
    console.log(chalk.bold.whiteBright(`IP yang Digunakan : ${ip}`));
    console.log(chalk.bold.cyanBright('='.repeat(80)));
    console.log();

    const tasks = await getTaskList(token, cookie, proxy);
    if (!tasks) return;

    for (const task of tasks) {
      if (!task.is_done) {
        await completeTask(token, task.task_id, address, task.text, cookie, proxy);
      } else {
        console.log(chalk.bold.grey(` ➥  Task Already Done: ${task.text}`));
      }
    }
    const contractAddress = '0xD615Eb3ea3DB2F994Dce7d471A02d521B8E1D22d';
    const contract = new ethers.Contract(contractAddress, contractAbi, wallet);
    console.log();
    await performCheckIn(wallet, contract, token, cookie, proxy);
    console.log();
    const credits = await getCredits(token, address, cookie, proxy);
    if (credits) {
      console.log();
      console.log(chalk.greenBright('Credits Detail:'));
      let total = 0;
      for (const [key, value] of Object.entries(credits)) {
        console.log(chalk.bold.cyanBright(` ➯ ${formatKey(key)}: ${value}`));
        total += value;
      }
      console.log(chalk.greenBright(`Total Credits: ${total}`));
    }

    console.log(chalk.yellowBright(`\nDone Processed Address: ${shorten(address)}`));
  } catch (error) {
    console.error(chalk.red(`\nError Process Address: ${error.message}`));
  }
}

async function processWallets(privateKeys, proxies, useProxy) {
  for (let i = 0; i < privateKeys.length; i++) {
    const privateKey = privateKeys[i];
    const proxy = useProxy && proxies.length > 0 ? proxies[i % proxies.length] : null;
    console.log();
    console.log(chalk.bold.cyanBright('='.repeat(80)));
    console.log(chalk.bold.whiteBright(`Account: ${i + 1}/${privateKeys.length}`));
    await processAccount(privateKey, proxy);
  }
  console.log();
  console.log(chalk.bold.cyanBright('='.repeat(80)));
  console.log(chalk.greenBright('All Account Already Proccessed.\n'));
  console.log(chalk.yellowBright('Wait 24 Hours Before Next Loop...'));
  setTimeout(() => processWallets(privateKeys, proxies, useProxy), 24 * 60 * 60 * 1000);
}

async function run() {
  cfonts.say('NT EXHAUST', {
    font: 'block',
    align: 'center',
    colors: ['cyan', 'magenta'],
    background: 'transparent',
    letterSpacing: 1,
    lineHeight: 1,
    space: true,
    maxLength: '0'
  });
  console.log(centerText("=== Telegram Channel 🚀 : NT Exhaust (@NTExhaust) ==="));
  console.log(centerText("✪ ByteNova Auto Daily Checkin & Task ✪ \n"));

  const useProxyAns = await askQuestion('Ingin menggunakan proxy? (y/n): ');
  const useProxy = useProxyAns.trim().toLowerCase() === 'y';
  let proxies = [];
  if (useProxy) {
    proxies = await readProxies();
    if (proxies.length === 0) {
      console.log(chalk.yellow('Proxy Not Availlable in Proxy.txt , Continue Without Proxy.'));
    }
  }

  const privateKeys = await readPrivateKeys();
  if (privateKeys.length === 0) {
    console.log(chalk.red(' No Private Key Not Found on pk.txt. Exit...'));
    return;
  }

  await processWallets(privateKeys, proxies, useProxy);
}

run().catch(error => console.error(chalk.red(`Error: ${error.message}`)));