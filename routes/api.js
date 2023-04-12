import express from 'express';
import multer from 'multer';
import os from 'os';
import fs from 'fs';

import { getFramesFromBuffer, processFrames } from '../parser/frameParser.js';

const apiRoutes = express.Router();

const upload = multer({ dest: os.tmpdir() });

apiRoutes.post('/upload', upload.single('file'), function(req, res) {
  
  const file = req.file;
  console.info(`File ${file.originalname} uploaded`)

  const readFileData = (file) => {
    let fileData = null;
    try {
      fileData = fs.readFileSync(file);
    } catch (e) {
      console.error('error reading file ', e)
    }
    return fileData;
  }

  let bufferData = readFileData(file.path);
  
  const { fileHeader, bufferFrames } = getFramesFromBuffer(bufferData);
  
  let frames = processFrames(fileHeader, bufferFrames);

  res.status(200).json(frames);

});

apiRoutes.route("/parse").post(function (req, res) {
    res.status(200).json(items);
});

export default apiRoutes;