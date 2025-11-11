require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');

const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('./db');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const saltRounds = 10;


// ✅ Auth Middleware
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, error: "Invalid token" });
    req.user = decoded;
    next();
  });
}


// ✅ Middleware to protect admin routes
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: Admins only' });
  }
  next();
}

// ✅ Test DB
app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS result');
    res.json({ success: true, db: rows[0].result });
  } catch (err) {
    console.error('Database connection failed:', err);
    res.status(500).json({ success: false, error: 'DB not connected' });
  }
});

// ✅ Pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/products', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'products.html'));
});

// ✅ Register
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length > 0) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    const token = jwt.sign({ id: result.insertId, email, name, role: 'customer' }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: result.insertId, name, email, role: 'customer' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ✅ Login (Customer)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await pool.query('INSERT INTO user_logins (user_id, login_time, ip_address) VALUES (?, NOW(), ?)', [user.id, req.ip]);

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ✅ Admin Login Route
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ error: 'Admin not found' });

    const user = users[0];

    if (user.role !== 'admin') return res.status(403).json({ error: 'Access denied: Not an admin' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
	
	    // ✅ Return both token and name
    res.json({ token, name: user.name });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: 'Admin login failed' });
  }
});



app.post('/api/submit-quote', async (req, res) => {
  const { name, email, quote } = req.body;
  const today = new Date().toISOString().split("T")[0];

  const topics = ['Hope', 'Kindness', 'Discipline', 'Creativity', 'Confidence'];
  const index = new Date().getDate() % topics.length;
  const topic = topics[index];

  if (!name || !email || !quote || quote.length < 5) {
    return res.status(400).json({ message: 'All fields are required and quote must be meaningful.' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT * FROM quotes WHERE email = ? AND date = ?',
      [email, today]
    );
    if (existing.length > 0) {
      return res.status(400).json({ message: 'You already submitted today.' });
    }

    await pool.query(
      'INSERT INTO quotes (name, email, quote_text, topic, date) VALUES (?, ?, ?, ?, ?)',
      [name, email, quote, topic, today]
    );

    res.json({ message: 'Quote submitted successfully!' });
  } catch (err) {
    console.error('Quote insert error:', err);
    res.status(500).json({ message: 'Submission failed.' });
  }
});

app.get('/api/daily-topic', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT topic FROM quote_topic ORDER BY id DESC LIMIT 1');
    const topic = result.length > 0 ? result[0].topic : "Inspiration";
    res.json({ topic });
  } catch (err) {
    console.error('Failed to fetch daily topic:', err);
    res.status(500).json({ topic: "Inspiration" });
  }
});

app.get('/api/admin/quotes', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [quotes] = await pool.query('SELECT * FROM quotes ORDER BY date DESC, id DESC');
    res.json(quotes);
  } catch (err) {
    console.error("Admin fetch quotes failed:", err);
    res.status(500).json({ error: 'Failed to fetch quotes' });
  }
});

app.post('/api/admin/select-winner', authenticateToken, isAdmin, async (req, res) => {
  const { quoteId } = req.body;

  try {
    // Mark as winner
    await pool.query('UPDATE quotes SET is_winner = 1 WHERE id = ?', [quoteId]);

    // Get winner email
    const [rows] = await pool.query('SELECT name, email FROM quotes WHERE id = ?', [quoteId]);
    if (rows.length === 0) return res.status(404).json({ message: 'Quote not found' });

    const { name, email } = rows[0];

    // Create coupon
    const couponCode = 'WIN' + Math.random().toString(36).substring(2, 10).toUpperCase();
    const validUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await pool.query(
      'INSERT INTO coupons (email, code, discount_percent, valid_until) VALUES (?, ?, ?, ?)',
      [email, couponCode, 20, validUntil]
    );

    // Send coupon via email
    await transporter.sendMail({
      from: `"Mens Tees Hub" <${process.env.MAIL_USER}>`,
      to: email,
      subject: "🎉 You've Won a Coupon!",
      html: `
        <p>Hi ${name},</p>
        <p>🎉 Congratulations! Your quote has been selected as the winner.</p>
        <p>Use this coupon on your next purchase:</p>
        <h2 style="color:#007bff">${couponCode}</h2>
        <p>This coupon gives you <b>20% OFF</b> and is valid for 7 days.</p>
        <p>Thank you for being part of the community!</p>
        <hr>
        <p><small>This coupon can be used only once.</small></p>
      `
    });

    res.json({ message: `Winner selected and coupon sent to ${email}` });
  } catch (err) {
    console.error("Select winner failed:", err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

app.get('/api/admin/coupons', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [coupons] = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    res.json(coupons);
  } catch (err) {
    console.error("Failed to fetch coupons:", err);
    res.status(500).json({ error: 'Failed to load coupons' });
  }
});

app.post('/api/admin/set-topic', authenticateToken, isAdmin, async (req, res) => {
  const { topic } = req.body;

  if (!topic || topic.length < 3) {
    return res.status(400).json({ error: "Topic is too short" });
  }

  try {
    await pool.query('INSERT INTO quote_topic (topic) VALUES (?)', [topic]);
    res.json({ message: "Topic updated successfully" });
  } catch (err) {
    console.error("Set topic error:", err);
    res.status(500).json({ error: "Failed to set topic" });
  }
});

app.get('/api/daily-topic', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT topic FROM quote_topic ORDER BY id DESC LIMIT 1');
    const topic = result.length > 0 ? result[0].topic : "Inspiration";
    res.json({ topic });
  } catch (err) {
    console.error('Failed to fetch daily topic:', err);
    res.status(500).json({ topic: "Inspiration" });
  }
});










const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});



// ✅ Admin Route: Get All Products
app.get('/api/admin/products', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json({ success: true, products });
  } catch (err) {
    console.error('Fetch products failed:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch products' });
  }
});

// ✅ Admin Route: Get All Orders
app.get('/api/admin/orders', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id AS order_id,
        o.order_number,
        o.total_amount,
        o.status,
        o.created_at,
        o.shipping_address,
        o.billing_address,
        o.payment_method,
        u.name AS customer_name,
        u.email AS customer_email
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `);

    for (const order of orders) {
      const [items] = await pool.query(`
        SELECT product_name AS product, quantity, size
        FROM order_items
        WHERE order_id = ?
      `, [order.order_id]);
      order.items = items;
    }

    res.json({ success: true, orders });
  } catch (err) {
    console.error("Failed to fetch admin orders:", err);
    res.status(500).json({ success: false, error: "Failed to fetch orders" });
  }
});

// ✅ Customer Route: Get Their Orders
app.get('/api/my-orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT id, order_number, total_amount, status, shipping_address, created_at
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [req.user.id]);

    for (const order of orders) {
      const [items] = await pool.query(`
        SELECT product_name AS product, product_price AS price, size, quantity
        FROM order_items
        WHERE order_id = ?
      `, [order.id]);

      order.items = items;
    }

    res.json({ success: true, orders });
  } catch (err) {
    console.error("Error fetching my orders:", err);
    res.status(500).json({ success: false, error: "Could not fetch orders" });
  }
});

app.get('/api/admin/quotes', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [quotes] = await pool.query(`
      SELECT q.*, u.name, u.email
      FROM quotes q
      JOIN users u ON q.user_id = u.id
      ORDER BY q.date DESC, q.id DESC
    `);
    res.json(quotes);
  } catch (err) {
    console.error('Error fetching quotes:', err);
    res.status(500).json({ error: 'Failed to fetch quotes' });
  }
});


// ✅ Admin Route: Update Order Status
app.put('/api/admin/update-status', authenticateToken, isAdmin, async (req, res) => {
  const { orderId, newStatus } = req.body;

  if (!orderId || !newStatus) {
    return res.status(400).json({ success: false, error: "Missing order ID or status" });
  }

  try {
    await pool.query('UPDATE orders SET status = ? WHERE id = ?', [newStatus, orderId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Failed to update order status:", err);
    res.status(500).json({ success: false, error: "Failed to update order status" });
  }
});

app.post('/api/admin/products', authenticateToken, isAdmin, async (req, res) => {
  let { name, price, category_id, image_url } = req.body;

  name = name?.trim();
  image_url = image_url?.trim();
  price = parseFloat(price);
  category_id = parseInt(category_id);

  if (!name || !category_id || !image_url || isNaN(price) || price <= 0) {
    return res.status(400).json({ error: 'All fields are required and price must be a valid number > 0' });
  }

  try {
    const [result] = await pool.query(
  'INSERT INTO products (name, price, category_id, image_url, is_active) VALUES (?, ?, ?, ?, 1)',
  [name, price, category_id, image_url]
);

    res.json({ success: true, productId: result.insertId });
  } catch (err) {
    console.error('Add product failed:', err);
    res.status(500).json({ error: 'Add product failed' });
  }
});

app.put('/api/admin/products/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, category_id, image_url } = req.body;

  try {
    await pool.query(
      'UPDATE products SET name = ?, price = ?, category_id = ?, image_url = ? WHERE id = ?',
      [name, price, category_id, image_url, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Update product failed:', err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// ✅ Admin Route: Add Product
app.post('/api/admin/products', authenticateToken, isAdmin, async (req, res) => {
  let { name, price, category_id, image_url } = req.body;

  name = name?.trim();
  image_url = image_url?.trim();
  price = parseFloat(price);
  category_id = parseInt(category_id);

  if (!name || !image_url || isNaN(price) || price <= 0 || isNaN(category_id)) {
    return res.status(400).json({ error: 'All fields are required and must be valid' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO products (name, price, category_id, image_url, is_active) VALUES (?, ?, ?, ?, 1)',
      [name, price, category_id, image_url]
    );
    res.json({ success: true, productId: result.insertId });
  } catch (err) {
    console.error('Add product failed:', err);
    res.status(500).json({ error: 'Add product failed' });
  }
});

// ✅ Admin Route: Edit Product
app.put('/api/admin/products/:id', isAdmin, async (req, res) => {
  console.log("PUT /api/admin/products/:id called", req.body); // ✅ Add here

  const { name, price, category_id, image_url } = req.body;
  const { id } = req.params;

  try {
    await pool.query(
      'UPDATE products SET name = ?, price = ?, category_id = ?, image_url = ?, updated_at = NOW() WHERE id = ?',
      [name, price, category_id, image_url, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Update product failed:", err);
    res.status(500).json({ success: false, error: "Failed to update product" });
  }
});



// ✅ Admin Route: Delete Product
app.delete('/api/admin/products/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM products WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete product failed:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const [products] = await pool.query(`
      SELECT 
        p.id, p.name, p.price, p.image_url, c.name AS category 
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      WHERE p.is_active = 1
      ORDER BY p.created_at DESC
    `);
    res.json({ success: true, products });
  } catch (err) {
    console.error("Failed to load products:", err);
    res.status(500).json({ success: false, error: "Failed to load products" });
  }
});



app.post('/api/checkout', authenticateToken, async (req, res) => {
  console.log('🎯 CHECKOUT ENDPOINT CALLED');
  
  const { cart, total, paymentMethod, address } = req.body;

  // Basic validation
  if (!cart || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ success: false, error: "Cart is empty" });
  }

  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    console.log('✅ Transaction started');

    // Check if user exists (simpler query)
    const [users] = await connection.query(
      'SELECT id, name FROM users WHERE id = ?', 
      [req.user.id]
    );
    
    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const user = users[0];
    const orderNumber = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5).toUpperCase();

    console.log('📦 Creating order:', orderNumber);

    // Insert order (simplified - remove billing_address if it causes issues)
    const [orderResult] = await connection.query(
      `INSERT INTO orders 
        (user_id, order_number, total_amount, status, shipping_address, payment_method, payment_status) 
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        orderNumber,
        total,
        'pending',
        address || 'Cash on Delivery - Address to be provided',
        paymentMethod,
        'pending'
      ]
    );

    const orderId = orderResult.insertId;
    console.log('✅ Order created with ID:', orderId);

    // Insert order items
    for (const item of cart) {
      await connection.query(
        `INSERT INTO order_items 
          (order_id, product_id, product_name, product_price, size, quantity, image_url)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          orderId,
          item.id || null,
          item.title || 'Unknown Product',
          item.price || 0,
          item.selectedSize || 'M',
          item.quantity || 1,
          item.image || ''
        ]
      );
    }

    await connection.commit();
    console.log('🎉 Checkout completed successfully');

    res.json({ 
      success: true, 
      orderId: orderId,
      orderNumber: orderNumber
    });

  } catch (err) {
    await connection.rollback();
    console.error('❌ CHECKOUT ERROR:', err);
    console.error('Error details:', {
      code: err.code,
      message: err.message,
      sqlMessage: err.sqlMessage
    });
    
    res.status(500).json({ 
      success: false, 
      error: "Checkout failed",
      details: err.message 
    });
  } finally {
    connection.release();
  }
});






app.post('/api/calculate-size', (req, res) => {
  const { height, weight, chest, fit, preference } = req.body;

  if (!height || !weight || !chest || !fit || !preference) {
    return res.status(400).json({ error: "Missing inputs" });
  }

  // Dummy logic – you can replace this with ML or real logic
  let size = "M";
  if (chest < 36 || weight < 55) size = "S";
  else if (chest >= 40 || weight > 75) size = "L";
  if (fit === "loose") size = getNext(size);
  if (fit === "tight") size = getPrev(size);

  return res.json({ size });
});

function getPrev(size) {
  const sizes = ["XS", "S", "M", "L", "XL", "XXL"];
  const index = sizes.indexOf(size);
  return index > 0 ? sizes[index - 1] : size;
}

function getNext(size) {
  const sizes = ["XS", "S", "M", "L", "XL", "XXL"];
  const index = sizes.indexOf(size);
  return index < sizes.length - 1 ? sizes[index + 1] : size;
}

// ✅ GET today's topic
app.get('/api/daily-topic', (req, res) => {
  const topics = ['Hope', 'Confidence', 'Dreams', 'Kindness', 'Discipline'];
  const index = new Date().getDate() % topics.length;
  res.json({ topic: topics[index] });
});

// ✅ POST: Submit quote
app.post('/api/submit-quote', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const quote = req.body.quote;
  const today = new Date().toISOString().split("T")[0];

  const topics = ['Hope', 'Confidence', 'Dreams', 'Kindness', 'Discipline'];
  const index = new Date().getDate() % topics.length;
  const topic = topics[index];

  if (!quote || quote.length < 5) {
    return res.status(400).json({ message: 'Quote too short' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT * FROM quotes WHERE user_id = ? AND date = ?',
      [userId, today]
    );
    if (existing.length > 0) {
      return res.status(400).json({ message: 'You already submitted today' });
    }

    await pool.query(
      'INSERT INTO quotes (user_id, quote_text, topic, date) VALUES (?, ?, ?, ?)',
      [userId, quote, topic, today]
    );

    res.json({ message: 'Quote submitted successfully!' });
  } catch (err) {
    console.error('Quote submission error:', err);
    res.status(500).json({ message: 'Submission failed' });
  }
});


// ✅ Error Handlers
app.use((req, res) => res.status(404).send('Page not found'));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});


// ✅ Always send JSON for unknown routes
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// ✅ Global error handler must also return JSON
app.use((err, req, res, next) => {
  console.error("🔥 Unhandled Error:", err.stack);
  res.status(500).json({ success: false, error: 'Server error occurred' });
});



const axios = require("axios");



app.use(express.json());

app.post("/api/payment", async (req, res) => {
  const { name, email, phone, amount } = req.body;

  const payload = {
    purpose: "T-Shirt Order Payment",
    amount: amount,
    buyer_name: name,
    email: email,
    phone: phone,
    redirect_url: "http://localhost:5500/success.html", // ✅ Change if needed
    send_email: true,
    send_sms: true,
    allow_repeated_payments: false
  };

  try {
    const response = await axios.post(
      "https://www.instamojo.com/api/1.1/payment-requests/",
      payload,
      {
        headers: {
          "X-Api-Key": "bd61d4fe2b52dd3ca5eb0a74154c894",       // ✅ Your LIVE API KEY
          "X-Auth-Token": "101fed1ad33f82ae9fe04914efc5a360c"     // ✅ Your LIVE AUTH TOKEN
        }
      }
    );

    const paymentUrl = response.data.payment_request.longurl;
    res.json({ success: true, url: paymentUrl });

  } catch (error) {
    console.error("Instamojo Error:", error.response?.data || error.message);
    res.status(500).json({ success: false, message: "Payment API failed" });
  }
});








// ✅ Start Server


app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});

