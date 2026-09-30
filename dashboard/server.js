const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = 3000;
const PYTHON_API_URL = "http://127.0.0.1:5000/api/unblock";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let blockedList = [];
let totalPacketsObserved = 0;

// পাইথন ইঞ্জিন থেকে ইভেন্ট রিসিভ
app.post('/api/event', (req, res) => {
  const event = req.body;

  if (event.type === 'BLOCK') {
    // ডুপ্লিকেট এভয়েড করা
    if (!blockedList.some(item => item.ip === event.ip)) {
      blockedList.unshift(event);
      if (blockedList.length > 50) blockedList.pop();
    }
    io.emit('threat-blocked', event);
  } else if (event.type === 'UNBLOCK') {
    blockedList = blockedList.filter(item => item.ip !== event.ip);
    io.emit('threat-unblocked', { ip: event.ip });
  } else if (event.type === 'TRAFFIC') {
    totalPacketsObserved++;
    io.emit('traffic-stream', event);
  }

  res.sendStatus(200);
});

// ফ্রন্টএন্ড থেকে আনব্লক রিকোয়েস্ট হ্যান্ডলার
app.post('/api/unblock', async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });

  try {
    // নেটিভ fetch ব্যবহার করে পাইথন সার্ভিসকে কল করা
    const pyResponse = await fetch(PYTHON_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });

    if (pyResponse.ok) {
      blockedList = blockedList.filter(item => item.ip !== ip);
      io.emit('threat-unblocked', { ip });
      return res.json({ success: true, ip });
    } else {
      return res.status(500).json({ error: "Firewall engine rejected unblock" });
    }
  } catch (err) {
    return res.status(502).json({ error: "Failed to connect to Python Engine" });
  }
});

io.on('connection', (socket) => {
  socket.emit('init-state', {
    blocked: blockedList,
    totalPackets: totalPacketsObserved
  });
});

server.listen(PORT, () => {
  console.log(`[+] Dashboard running at: http://localhost:${PORT}`);
});