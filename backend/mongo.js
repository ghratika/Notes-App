const mongoose = require('mongoose');

if (process.argv.length < 3) {
  console.log('give password as argument');
  process.exit(1);
}

const password = process.argv[2];
const password = process.env.MONGODB_PASSWORD;
if (!password) {
  console.log(
    'Please provide the password as an argument: node mongo.js <password>'
  );
  process.exit(1);

const url = process.env.MONGODB_URL;

mongoose.set('strictQuery', false);
mongoose.connect(url).then(() => {
  const noteSchema = new mongoose.Schema({
    content: String,
    important: Boolean,
  });

  const Note = mongoose.model('Note', noteSchema);

  /*
  const note = new Note({
    content: 'HTML is x',
    important: true,
  })

  note.save().then(result => {
    console.log('note saved!')
    mongoose.connection.close()
  })
  */
  Note.find({}).then((result) => {
    result.forEach((note) => {
      console.log(note);
    });
    mongoose.connection.close();
  });
});

// const mongoose = require('mongoose');

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
//   content: String,
//   date: Date,
//   important: Boolean,
// });

// const Note = mongoose.model('Note', noteSchema);

// const note = new Note({
//   content: 'HTML is Easy',
//   date: new Date(),
//   important: true,
// });

// Note.find({}).then((result) => {
//   result.forEach((note) => {
//     console.log(note);
//   });
//   mongoose.connection.close();
// });
// note
//   .save()
//   .then((result) => {
//     console.log('note saved!');
//     mongoose.connection.close();
//   })
//   .catch((error) => {
//     console.log('error saving note:', error);
//     mongoose.connection.close();
//   });
