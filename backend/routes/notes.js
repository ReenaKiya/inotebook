const express = require('express')
const Note = require('../models/Note')
const router = express.Router();
var fetchuser = require('../middleware/fetchuser')
const { body, validationResult } = require('express-validator');



//ROUTE 1:Get all the Notes using:GET "/api/notes/fetchallnotes".  login required

router.get('/fetchallnotes', fetchuser, async (req, res) => {

  try {
    const notes = await Note.find({ user: req.user.id })

    res.json(notes)
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})


//ROUTE 2:Add a new Note using:POST "/api/notes/addnote".  login required

router.post('/addnote', fetchuser, [
  body('title', 'Enter a valid title').isLength({ min: 3 }),
  body('discription', 'discription must be atleast 5 characters').isLength({ min: 5 }),
], async (req, res) => {
  try {
    const { title, discription, tag, } = req.body;

    // if there are errors, return bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const note = new Note({
      title, discription, tag, user: req.user.id
    })
    const savedNote = await note.save()

    res.json(savedNote)
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})

//ROUTE 3:Update an exiting Note using:PUT "/api/notes/updatenote".  login required
router.put('/updatenote/:id', fetchuser, async (req, res) => {
  const { title, discription, tag } = req.body;
  try {
    //Create a newNote Object
    const newNote = {};
    if (title) { newNote.title = title };
    if (discription) { newNote.discription = discription };
    if (tag) { newNote.tag = tag };
    //Find the note to be updated and update it
    let note = await Note.findById(req.params.id)
    if (!note) { return res.status(404).send("Not Found") }
    if (note.user.toString() !== req.user.id) {
      return res.status(401).send("Not Allowed")
    }
    note = await Note.findByIdAndUpdate(req.params.id, { $set: newNote }, { new: true })
    res.json({ note })
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})




//ROUTE 4:Delete an exiting Note using:DELETE "/api/notes/deletenote".  login required
router.delete('/deletenote/:id', fetchuser, async (req, res) => {
  try {

    //Find the note to be delete and delete it
    let note = await Note.findById(req.params.id)
    if (!note) { return res.status(404).send("Not Found") }

    //Allow deletion only if user owns this note
    if (note.user.toString() !== req.user.id) {
      return res.status(401).send("Not Allowed")
    }
    note = await Note.findByIdAndDelete(req.params.id)
    res.json({ "Success": "Note has been deleted", note: note })

  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error")
  }
})

module.exports = router