const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());

let users = [];
let posts = [];

// Middleware to check if the user is authenticated
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (token == null) return res.sendStatus(401);
  
  jwt.verify(token, 'secretKey', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Route to register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if user already exists
  const userExists = users.find(user => user.username === username);
  if (userExists) return res.status(400).send('User already exists');

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  res.status(201).send('User registered');
});

// Route to login and get a token
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(user => user.username === username);
  if (!user) return res.status(400).send('User not found');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid password');

  const token = jwt.sign({ username: user.username }, 'secretKey');
  res.json({ token });
});

// Route to get all posts (only authenticated users can access)
app.get('/posts', authenticateToken, (req, res) => {
  res.json(posts);
});

// Route to create a new post (only authenticated users can access)
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;

  const newPost = {
    id: posts.length + 1,
    title,
    content,
    author: req.user.username
  };

  posts.push(newPost);
  res.status(201).json(newPost);
});

// Route to get a post by ID (only authenticated users can access)
app.get('/posts/:id', authenticateToken, (req, res) => {
  const post = posts.find(post => post.id === parseInt(req.params.id));
  if (!post) return res.status(404).send('Post not found');
  
  res.json(post);
});

// Route to update a post (only authenticated users can access)
app.put('/posts/:id', authenticateToken, (req, res) => {
  const post = posts.find(post => post.id === parseInt(req.params.id));
  if (!post) return res.status(404).send('Post not found');
  
  if (post.author !== req.user.username) return res.status(403).send('You can only edit your own posts');
  
  const { title, content } = req.body;
  post.title = title;
  post.content = content;

  res.json(post);
});

// Route to delete a post (only authenticated users can access)
app.delete('/posts/:id', authenticateToken, (req, res) => {
  const postIndex = posts.findIndex(post => post.id === parseInt(req.params.id));
  if (postIndex === -1) return res.status(404).send('Post not found');
  
  if (posts[postIndex].author !== req.user.username) return res.status(403).send('You can only delete your own posts');
  
  posts.splice(postIndex, 1);
  res.status(204).send();
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
