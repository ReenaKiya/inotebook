const mongoose = require('mongoose');
const mongoURI = "mongodb://127.0.0.1:27017/inotebook"

const connectToMongo = () => {
  mongoose.connect(mongoURI)
    .then((success) => connectedsuccessfully)
    .catch(err => console.log(err.message))
}

module.exports = connectToMongo;