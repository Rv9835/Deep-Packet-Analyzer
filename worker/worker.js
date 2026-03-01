// worker that pulls job IDs from Redis, downloads PCAP via signed URL,
// invokes the DPI engine binary, and reports completion back to the web API.
const axios = require('axios');
const Redis = require('ioredis');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const API_URL = process.env.API_URL || 'http://localhost:3000';
const redis = new Redis(process.env.REDIS_URL);
const QUEUE_KEY = 'dpi_jobs';
const API_KEY = process.env.API_KEY || 'secret';

async function processJob(id) {
    try {
        console.log('processing job', id);
        // fetch job details from web API
        const jobResp = await axios.get(`${API_URL}/jobs/${id}`, { headers: {'x-api-key': API_KEY} });
        const job = jobResp.data;
        if (job.status !== 'queued') return;
        // get signed url for pcap download
        const getUrlResp = await axios.get(`${API_URL}/signed-url`, { params:{ key: job.pcapKey, verb:'get' }, headers:{'x-api-key':API_KEY} });
        const pcapUrl = getUrlResp.data.url;
        // download to local file
        const localPcap = path.join('/tmp', `job_${id}.pcap`);
        const writer = fs.createWriteStream(localPcap);
        const resp = await axios.get(pcapUrl, { responseType:'stream' });
        resp.data.pipe(writer);
        await new Promise((r,e)=> writer.on('finish',r).on('error',e));

        // similarly fetch ruleset file via signed URL (not shown for brevity)
        // run the DPI engine binary
        const outdir = `/tmp/job_${id}_out`;
        fs.mkdirSync(outdir, { recursive:true });
        await new Promise((resolve,reject) => {
            const bin = spawn('dpi_engine', [localPcap, job.ruleset, outdir]);
            bin.on('close', code => {
                if (code === 0) resolve(); else reject(new Error('engine failed ' + code));
            });
        });
        // after execution, upload artifacts back to S3 using signed URLs (not implemented)
        // notify web API
        await axios.post(`${API_URL}/jobs/${id}/complete`, { artifact: { reportKey: `reports/${id}.json` } }, { headers:{'x-api-key':API_KEY} });
        console.log('job',id,'completed');
    } catch (err) {
        console.error('error processing job', id, err.message);
    }
}

async function pollQueue() {
    try {
        const id = await redis.lpop(QUEUE_KEY);
        if (id) {
            await processJob(parseInt(id,10));
        }
    } catch (err) {
        console.error('redis error', err.message);
    }
}

setInterval(pollQueue, 2000);
console.log('worker started');
