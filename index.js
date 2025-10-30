const express = require('express')
const app = express()
const cors = require('cors')
const bcrypt = require('bcrypt')
const saltRounds = 10
const { v4: uuidv4 } = require('uuid')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const cookieSession = require('cookie-session')
const { createClient } = require('@supabase/supabase-js')

const supabaseUrl = 'https://pmjvbpmtdwntpinsqach.supabase.co'
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBtanZicG10ZHdudHBpbnNxYWNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE3MTc5NTcsImV4cCI6MjA3NzI5Mzk1N30.uKyhkf6XPncz70aH58Olpivv7QG4zBt6CWsyayAfcZk'
const supabase = createClient(supabaseUrl, supabaseKey)

app.use(express.json())
app.use(cookieParser())

app.set('trust proxy', 1)
app.use(cookieSession({
    name: 'session',
    keys: ["crischatkey"],
    maxAge: 24 * 60 * 60 * 1000 
}))

app.use(bodyParser.urlencoded({ extended: false }))

app.use(bodyParser.json())

const corsOption = {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true,
    optionsSuccessStatus: 200
}
app.use(cors(corsOption))

app.use(session({
    key: "user",
    secret: "someRandomS3cr3ts",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    sameSite: 'none',
    cookie: {
        secure: true, 
        sameSite: 'none',
    }
}))

app.post('/api/register', cors(corsOption), async (req, res) => {
  const { firstname, lastname, username, password } = req.body

  try {
    const hash = await bcrypt.hash(password, saltRounds)

    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          username,
          password: hash,
          firstname,
          lastname,
          contacts: ''
        }
      ])

    if (error) {
      console.error('Supabase insert error:', error)
      return res.status(500).json({ error: 'Failed to insert user', details: error.message })
    }

    res.json({ message: `${username} has been added`, data })
  } catch (err) {
    console.error('Server error:', err)
    res.status(500).json({ error: 'Server error', details: err.message })
  }
})

app.post('/api/login', cors(corsOption), async (req, res) => {
  const { username, password } = req.body

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, password, firstname, lastname, contacts')
      .eq('username', username)
      .maybeSingle()

    if (error) {
      console.error('Supabase select error:', error)
      return res.status(500).json({ loggedIn: false, message: 'Database error', details: error.message })
    }

    if (!user) {
      return res.status(401).json({ loggedIn: false, message: "User doesn't exist" })
    }

    const ok = await bcrypt.compare(password, user.password)
    if (!ok) {
      return res.status(401).json({ loggedIn: false, message: 'Wrong username/password combination!' })
    }

    const sessionId = uuidv4()
    req.session.userId = user.id
    req.session.username = user.username
    req.session.sessionId = sessionId

    const { password: _redacted, ...safeUser } = user
    return res.json({
      loggedIn: true,
      sessionId,
      user: safeUser,
    })
  } catch (err) {
    console.error('Login server error:', err)
    return res.status(500).json({ loggedIn: false, message: 'Server error', details: err.message })
  }
})

function ensureAuth(req, res) {
  const uid = req.session?.userId
  if (!uid) {
    res.status(401).json({ loggedIn: false, message: 'Not authenticated' })
    return null
  }
  return uid
}

/**
 * GET /api/login
 * Return session status + (optionally) a fresh user payload from Supabase.
 */
app.get('/api/login', cors(corsOption), async (req, res) => {
  const uid = req.session?.userId
  if (!uid) return res.json({ loggedIn: false })

  // fetch minimal user snapshot (optional; you can return only session if you prefer)
  const { data: user, error } = await supabase
    .from('users')
    .select('id, username, firstname, lastname, contacts')
    .eq('id', uid)
    .maybeSingle()

  if (error) {
    console.error('Supabase error:', error)
    return res.json({ loggedIn: true, user: { id: uid, username: req.session.username } })
  }

  res.json({ loggedIn: true, user })
})

/**
 * GET /api/loggedInUser
 * Return the current user fields (fresh from DB).
 */
app.get('/api/loggedInUser', cors(corsOption), async (req, res) => {
  const uid = ensureAuth(req, res)
  if (!uid) return

  const { data: user, error } = await supabase
    .from('users')
    .select('id, username, firstname, lastname')
    .eq('id', uid)
    .maybeSingle()

  if (error) {
    console.error('Supabase error:', error)
    return res.status(500).json({ message: 'Database error', details: error.message })
  }

  if (!user) return res.status(404).json({ message: 'User not found' })
  res.json(user)
})

/**
 * POST /api/logout
 * Destroy the session.
 */
app.post('/api/logout', cors(corsOption), (req, res) => {
  // if you’re using cookie-session:
  req.session = null
  // if using express-session:
  // req.session.destroy(() => {})
  res.json({ loggedIn: false })
})

/**
 * GET /api/users
 * Get your contact list (users you’ve chatted with) ordered by latest chat date with you.
 * We’ll:
 *  1) read your contacts (comma-separated ids)
 *  2) fetch those users
 *  3) fetch chats involving you + any of them
 *  4) compute latest message timestamp per contact, sort desc
 */
app.get('/api/users', cors(corsOption), async (req, res) => {
  const me = ensureAuth(req, res)
  if (!me) return

  // read my contacts
  const { data: meRow, error: meErr } = await supabase
    .from('users')
    .select('contacts')
    .eq('id', me)
    .maybeSingle()

  if (meErr) {
    console.error('Supabase error:', meErr)
    return res.status(500).json([])
  }

  const contactsStr = meRow?.contacts || ''
  if (!contactsStr.trim()) return res.json([])

  // normalize list of IDs (your schema stores raw commas like "2,5,9")
  const contactIds = contactsStr.split(',').map(s => s.trim()).filter(Boolean).map(Number)
  if (!contactIds.length) return res.json([])

  // fetch those users’ basic info
  const { data: users, error: usersErr } = await supabase
    .from('users')
    .select('id, firstname, lastname, username')
    .in('id', contactIds)

  if (usersErr) {
    console.error('Supabase error:', usersErr)
    return res.status(500).json([])
  }

  // fetch chats that involve me AND any of those contacts
  // condition: (firstuser_id = me AND seconduser_id IN contacts) OR (firstuser_id IN contacts AND seconduser_id = me)
  const { data: chats, error: chatsErr } = await supabase
    .from('chat')
    .select('chat_id, date_sent, firstuser_id, seconduser_id')
    .or(
      `and(firstuser_id.eq.${me},seconduser_id.in.(${contactIds.join(
        ','
      )})),and(firstuser_id.in.(${contactIds.join(',')}),seconduser_id.eq.${me})`
    )
    .order('date_sent', { ascending: false })

  if (chatsErr) {
    console.error('Supabase error:', chatsErr)
    // still return the users without ordering by last chat if chat query failed
    return res.json(users)
  }

  // compute latest chat per contact
  const latestByContact = new Map()
  for (const c of chats) {
    const other = c.firstuser_id === me ? c.seconduser_id : c.firstuser_id
    if (!contactIds.includes(other)) continue
    if (!latestByContact.has(other)) {
      latestByContact.set(other, c.date_sent)
    }
  }

  // merge + sort
  const result = users
    .map(u => ({
      ...u,
      lastMessageAt: latestByContact.get(u.id) || null,
    }))
    .sort((a, b) => {
      const ta = a.lastMessageAt ? Date.parse(a.lastMessageAt) : 0
      const tb = b.lastMessageAt ? Date.parse(b.lastMessageAt) : 0
      return tb - ta
    })

  res.json(result)
})

/**
 * POST /api/send
 * Body: { message, to }
 * Ensure both sides have each other in contacts, then insert chat row.
 */
app.post('/api/send', cors(corsOption), async (req, res) => {
  const me = ensureAuth(req, res)
  if (!me) return
  const { message, to } = req.body
  const toId = Number(to)

  try {
    // read current contacts for me & them
    const [{ data: meRow }, { data: youRow }] = await Promise.all([
      supabase.from('users').select('contacts').eq('id', me).maybeSingle(),
      supabase.from('users').select('contacts').eq('id', toId).maybeSingle(),
    ])

    const meContacts = (meRow?.contacts || '').split(',').map(s => s.trim()).filter(Boolean)
    const youContacts = (youRow?.contacts || '').split(',').map(s => s.trim()).filter(Boolean)

    // add if missing
    if (!meContacts.includes(String(toId))) meContacts.push(String(toId))
    if (!youContacts.includes(String(me))) youContacts.push(String(me))

    // update contacts (only if changed)
    await Promise.all([
      supabase.from('users').update({ contacts: meContacts.join(',') }).eq('id', me),
      supabase.from('users').update({ contacts: youContacts.join(',') }).eq('id', toId),
    ])

    // insert chat
    const { error: chatErr } = await supabase.from('chat').insert([
      {
        chat_message: message,
        date_sent: new Date().toISOString(),
        firstuser_id: me,
        seconduser_id: toId,
        view: null,
      },
    ])

    if (chatErr) {
      console.error('Supabase insert chat error:', chatErr)
      return res.status(500).json({ message: 'Failed to send' })
    }

    res.json({ message: 'done' })
  } catch (e) {
    console.error('Send error:', e)
    res.status(500).json({ message: 'Failed to send' })
  }
})

/**
 * POST /api/messages
 * Body: { id }  // the other user
 * Return all chats between me and id, ordered by date desc
 */
app.post('/api/messages', cors(corsOption), async (req, res) => {
  const me = ensureAuth(req, res)
  if (!me) return
  const { id } = req.body
  const other = Number(id)

  const { data, error } = await supabase
    .from('chat')
    .select('*')
    .or(
      `and(firstuser_id.eq.${me},seconduser_id.eq.${other}),and(firstuser_id.eq.${other},seconduser_id.eq.${me})`
    )
    .order('date_sent', { ascending: false })

  if (error) {
    console.error('Supabase chat fetch error:', error)
    return res.status(500).json([])
  }
  res.json(data)
})

/**
 * POST /api/deletemessage
 * Body: { chat_id }
 */
app.post('/api/deletemessage', cors(corsOption), async (req, res) => {
  const me = ensureAuth(req, res)
  if (!me) return
  const { chat_id } = req.body

  // (optional) ensure the message belongs to this conversation; skipping for parity with your version
  const { error } = await supabase.from('chat').delete().eq('chat_id', chat_id)
  if (error) {
    console.error('Supabase delete error:', error)
    return res.status(500).json({ message: 'Failed' })
  }
  res.json({ message: 'ok' })
})

/**
 * POST /api/searchusers
 * Body: { search }
 * Find users (not me) whose firstname OR lastname starts with `search` (case-insensitive).
 */
app.post('/api/searchusers', cors(corsOption), async (req, res) => {
  const me = ensureAuth(req, res)
  if (!me) return
  const { search } = req.body
  const pattern = `${search}%`

  // PostgREST OR syntax with ilike:
  const { data, error } = await supabase
    .from('users')
    .select('id, firstname, lastname, username')
    .neq('id', me)
    .or(`firstname.ilike.${pattern},lastname.ilike.${pattern}`)

  if (error) {
    console.error('Supabase search error:', error)
    return res.status(500).json([])
  }
  res.json(data)
})

const port = process.env.PORT || 3001

app.listen(port, ()=> {
    console.log("running on port 3001")
})
