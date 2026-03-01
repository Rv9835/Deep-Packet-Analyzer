const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());

// simple in-memory job store
const jobs = new Map();
let nextJobId = 1;

// generate a dummy signed URL (just random string) for uploads/downloads
function makeSignedUrl(key) {
    return `https://storage.example.com/${key}?sig=${crypto.randomBytes(8).toString('hex')}`;
}

app.post('/jobs', (req, res) => {
    const { pcapKey, ruleset } = req.body;
    if (!pcapKey || !ruleset) {
        return res.status(400).json({ error: 'pcapKey and ruleset required' });
    }
    const id = nextJobId++;
    const job = {
        id,
        status: 'draft',
        pcapKey,
        ruleset,
        createdAt: new Date().toISOString(),
        artifact: {}
    };
    jobs.set(id, job);
    res.json(job);
});

app.get('/jobs', (req, res) => {
    // simple list all jobs
    res.json(Array.from(jobs.values()));
});

app.get('/jobs/:id', (req, res) => {
    const id = parseInt(req.params.id, 10);
    const job = jobs.get(id);
    if (!job) return res.status(404).json({ error: 'not found' });
    res.json(job);
});

app.post('/jobs/:id/start', (req, res) => {
    const id = parseInt(req.params.id, 10);
    const job = jobs.get(id);
    if (!job) return res.status(404).json({ error: 'not found' });
    if (job.status !== 'draft' && job.status !== 'uploaded') {
        return res.status(409).json({ error: 'cannot start job in status '+job.status });
    }
    job.status = 'queued';
    // in a real system, push to Redis queue
    res.json(job);
});

app.get('/signed-url', (req, res) => {
    const { key } = req.query;
    if (!key) return res.status(400).json({ error: 'key required' });
    // verb=put/get indicates upload/download (ignored)
    res.json({ url: makeSignedUrl(key) });
});

// worker callbacks: update job status
app.post('/jobs/:id/complete', (req, res) => {
    const id = parseInt(req.params.id,10);
    const job = jobs.get(id);
    if (!job) return res.status(404).json({ error:'not found' });
    job.status = 'complete';
    job.artifact = req.body.artifact || {};
    res.json(job);
});

// static files for simple UI
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`web server listening on port ${PORT}`);
});
