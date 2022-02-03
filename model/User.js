const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        min: 1,
        max: 255
    },

    password: {
        type: String,
        required: true,
        max: 1024,
        min: 1
    },
});

module.exports = mongoose.model('User', userSchema);