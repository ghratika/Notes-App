const express = require('express');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
const cors = require('cors');

app.use(cors());

let notes = [
  {
    id: 1,
    content: 'HTML is easy',
    important: true,
  },
  {
    id: 2,
    content: 'Browser can execute only JavaScript',
    important: false,
  },
  {
    id: 3,
    content: 'GET and POST are the most important methods of HTTP protocol',
    important: true,
  },
];

// Route to get all notes
app.get('/api/notes', (req, res) => {
  res.json(notes);
});

// Route to get a single note by ID
app.get('/api/notes/:id', (req, res) => {
  const id = Number(req.params.id);
  const note = notes.find((note) => note.id === id);

  if (note) {
    res.json(note);
  } else {
    res.status(404).send({ error: 'Note not found' });
  }
});

// Route to create a new note
app.post('/api/notes', (req, res) => {
  const body = req.body;

  if (!body.content) {
    return res.status(400).json({
      error: 'Content missing',
    });
  }

  const note = {
    id: notes.length + 1,
    content: body.content,
    important: body.important || false,
  };

  notes = notes.concat(note);
  res.json(note);
});

// Route to delete a note by ID
app.delete('/api/notes/:id', (req, res) => {
  const id = Number(req.params.id);
  notes = notes.filter((note) => note.id !== id);
  res.status(204).end();
});

// const PORT = 3001;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
