const app = require('./app'); // The Express app
const config = require('./utils/config');
const logger = require('./utils/logger');
console.log(typeof app);
app.listen(config.PORT, () => {
  logger.info(`Server running on port ${config.PORT}`);
});

// const express = require('express');
// const app = express();

// // Middleware to parse JSON bodies
// app.use(express.json());
// const cors = require('cors');
// app.use(express.static('dist'));

// app.use(cors());
// const mongoose = require('mongoose');
// require('dotenv').config();
// const Note = require('./models/note');
// app.use(requestLogger);

// const requestLogger = (request, response, next) => {
//   console.log('Method:', request.method);
//   console.log('Path:  ', request.path);
//   console.log('Body:  ', request.body);
//   console.log('---');
//   next();
// };
// // if (process.argv.length < 3) {
// //   console.log(
// //     'Please provide the password as an argument: node mongo.js <password>'
// //   );
// //   process.exit(1);
// // }

// // const password = process.argv[2];
// const password = process.env.MONGODB_PASSWORD;
// if (!password) {
//   console.log(
//     'Please provide the password as an argument: node mongo.js <password>'
//   );
//   process.exit(1);
// }

// const url = process.env.MONGODB_URL;

// mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });

// const noteSchema = new mongoose.Schema({
//   content: {
//     type: String,
//     minLength: 5,
//     required: true,
//   },
//   important: Boolean,
// });

// // const Note = mongoose.model('Note', noteSchema);

// app.get('/api/notes/:id', (request, response, next) => {
//   Note.findById(request.params.id)
//     .then((note) => {
//       if (note) {
//         response.json(note);
//       } else {
//         response.status(404).end();
//       }
//     })
//     .catch((error) => next(error));
//   //   console.log(error);
//   //   response.status(400).send({ error: 'malformatted id' });
//   // });
// });

// let notes = [
//   {
//     id: 1,
//     content: 'HTML is easy',
//     important: true,
//   },
//   {
//     id: 2,
//     content: 'Browser can execute only JavaScript',
//     important: false,
//   },
//   {
//     id: 3,
//     content: 'GET and POST are the most important methods of HTTP protocol',
//     important: true,
//   },
// ];

// // Route to get all notes
// app.get('/api/notes', (req, res) => {
//   res.json(notes);
// });

// // Route to get a single note by ID
// app.get('/api/notes/:id', (req, res) => {
//   const id = Number(req.params.id);
//   const note = notes.find((note) => note.id === id);

//   if (note) {
//     res.json(note);
//   } else {
//     res.status(404).send({ error: 'Note not found' });
//   }
// });

// // Route to create a new note
// app.post('/api/notes', (request, response, next) => {
//   const body = request.body;

//   const note = new Note({
//     content: body.content,
//     important: body.important || false,
//   });

//   note
//     .save()
//     .then((savedNote) => {
//       response.json(savedNote);
//     })
//     .catch((error) => next(error));

//   if (body.content === undefined) {
//     return response.status(400).json({
//       error: 'Content missing',
//     });
//   }

//   notes = notes.concat(note);
//   response.json(note);
// });

// app.put('/api/notes/:id', (request, response, next) => {
//   const { content, important } = request.body;

//   const note = {
//     content: body.content,
//     important: body.important,
//   };

//   Note.findByIdAndUpdate(
//     request.params.id,
//     { content, important },
//     { new: true, runValidators: true, context: 'query' }
//   )
//     .then((updatedNote) => {
//       response.json(updatedNote);
//     })
//     .catch((error) => next(error));
// });

// const unknownEndpoint = (request, response) => {
//   response.status(404).send({ error: 'unknown endpoint' });
// };

// // handler of requests with unknown endpoint
// app.use(unknownEndpoint);

// const errorHandler = (error, request, response, next) => {
//   console.error(error.message);

//   if (error.name === 'CastError') {
//     return response.status(400).send({ error: 'malformatted id' });
//   } else if (error.name === 'ValidationError') {
//     return response.status(400).json({ error: error.message });
//   }

//   next(error);
// };

// // this has to be the last loaded middleware, also all the routes should be registered before this!
// app.use(errorHandler);

// // Route to delete a note by ID
// app.delete('/api/notes/:id', (request, response, next) => {
//   Note.findByIdAndDelete(request.params.id)
//     .then((result) => {
//       response.status(204).end();
//     })
//     .catch((error) => next(error));
// });

// // const PORT = 3001;
// // app.listen(PORT, () => {
// //   console.log(`Server running on port ${PORT}`);
// // });

// const PORT = process.env.PORT || 3001;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });
