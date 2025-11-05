require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Datastore = require('nedb-promises');
const { customAlphabet } = require('nanoid');

const nanoid = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 10);
const app = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

app.use(cors());
app.use(express.json());

// DB
const users = Datastore.create({ filename: __dirname + '/data/users.db', autoload: true });
const shipments = Datastore.create({ filename: __dirname + '/data/shipments.db', autoload: true });
const quotes = Datastore.create({ filename: __dirname + '/data/quotes.db', autoload: true });

// Helpers
function signToken(user){
  return jwt.sign({ sub: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'missing_token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e){
    return res.status(401).json({ error: 'invalid_token' });
  }
}

function trackingNumber(){
  return 'SC' + Date.now().toString(36).toUpperCase() + nanoid();
}

// Seed some shipments if empty
(async ()=>{
  const count = await shipments.count({});
  if(count === 0){
    const now = new Date().toISOString();
    await shipments.insert([
      { trackingNumber: trackingNumber(), customer:'Acme Corp', email:'ops@acme.com', origin:'Los Angeles', destination:'Tokyo', service:'Air', weight:'250', status:'In Transit', createdAt:now, updatedAt:now, events:[
        { id: nanoid(), time: now, status: 'Created', location: 'Los Angeles, US', note: 'Shipment created' },
        { id: nanoid(), time: now, status: 'In Transit', location: 'Honolulu, US', note: 'Departed via air' }
      ] },
      { trackingNumber: trackingNumber(), customer:'Beta LLC', email:'logistics@beta.com', origin:'Hamburg', destination:'New York', service:'Ocean', weight:'1200', status:'Created', createdAt:now, updatedAt:now, events:[
        { id: nanoid(), time: now, status: 'Created', location: 'Hamburg, DE', note: 'Booking confirmed' }
      ] },
    ]);
  }
})();

// Auth
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error:'missing_fields' });
  const existingCount = await users.count({});
  if(existingCount > 0){
    return res.status(403).json({ error: 'registration_closed' });
  }
  const hash = await bcrypt.hash(password, 10);
  const user = await users.insert({ email: email.toLowerCase(), password: hash, role:'admin', createdAt: new Date().toISOString() });
  const token = signToken(user);
  res.json({ token, user: { id: user._id, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error:'missing_fields' });
  const user = await users.findOne({ email: email.toLowerCase() });
  if(!user) return res.status(401).json({ error: 'invalid_credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if(!ok) return res.status(401).json({ error: 'invalid_credentials' });
  const token = signToken(user);
  res.json({ token, user: { id: user._id, email: user.email } });
});

// Public tracking
app.get('/api/track/:trackingNumber', async (req, res) => {
  const t = (req.params.trackingNumber || '').trim();
  const s = await shipments.findOne({ trackingNumber: new RegExp('^' + t + '$', 'i') });
  if(!s) return res.status(404).json({ error:'not_found' });
  res.json(s);
});

// Quotes
app.post('/api/quotes', async (req, res) => {
  const q = req.body || {};
  const now = new Date().toISOString();
  const doc = await quotes.insert({ ...q, status:'new', createdAt: now });
  res.status(201).json(doc);
});

app.get('/api/quotes', authMiddleware, async (req, res) => {
  const list = await quotes.cfind({}).sort({ createdAt: -1 }).exec();
  res.json(list);
});

app.patch('/api/quotes/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const patch = req.body || {};
  await quotes.update({ _id: id }, { $set: patch });
  const updated = await quotes.findOne({ _id: id });
  res.json(updated);
});

app.delete('/api/quotes/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await quotes.remove({ _id: id }, {});
  res.json({ ok: true });
});

// Shipments
app.get('/api/shipments', authMiddleware, async (req, res) => {
  const list = await shipments.cfind({}).sort({ createdAt: -1 }).exec();
  res.json(list);
});

app.post('/api/shipments', authMiddleware, async (req, res) => {
  const body = req.body || {};
  const now = new Date().toISOString();
  const doc = await shipments.insert({
    trackingNumber: trackingNumber(),
    customer: body.customer,
    email: body.email || '',
    origin: body.origin,
    destination: body.destination,
    service: body.service || 'Standard',
    weight: body.weight || '',
    status: body.status || 'Created',
    createdAt: now,
    updatedAt: now,
    events: body.events && Array.isArray(body.events) ? body.events : [ { id: nanoid(), time: now, status: 'Created', location: body.origin || '', note: 'Shipment created' } ],
  });
  res.status(201).json(doc);
});

app.patch('/api/shipments/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const patch = req.body || {};
  patch.updatedAt = new Date().toISOString();
  await shipments.update({ _id: id }, { $set: patch });
  const updated = await shipments.findOne({ _id: id });
  res.json(updated);
});

app.delete('/api/shipments/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await shipments.remove({ _id: id }, {});
  res.json({ ok: true });
});

// Tracking events
app.post('/api/shipments/:id/events', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const event = {
    id: nanoid(),
    time: body.time || new Date().toISOString(),
    status: body.status || 'In Transit',
    location: body.location || '',
    note: body.note || ''
  };
  const s = await shipments.findOne({ _id: id });
  if(!s) return res.status(404).json({ error:'not_found' });
  const events = Array.isArray(s.events) ? s.events : [];
  events.unshift(event);
  await shipments.update({ _id: id }, { $set: { events, updatedAt: new Date().toISOString(), status: body.status || s.status } });
  const updated = await shipments.findOne({ _id: id });
  res.status(201).json(updated);
});

app.delete('/api/shipments/:id/events/:eventId', authMiddleware, async (req, res) => {
  const { id, eventId } = req.params;
  const s = await shipments.findOne({ _id: id });
  if(!s) return res.status(404).json({ error:'not_found' });
  const events = (s.events || []).filter(ev => ev.id !== eventId);
  await shipments.update({ _id: id }, { $set: { events, updatedAt: new Date().toISOString() } });
  const updated = await shipments.findOne({ _id: id });
  res.json(updated);
});

app.get('/api/health', (req, res)=> res.json({ ok:true }));

app.listen(PORT, () => {
  console.log(`ShippingCo API listening on :${PORT}`);
});
