import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Initialize variables to store the last received and sent messages
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // TODO implement the status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to get the last received message
  _user.get('/getLastReceivedMessage', (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route to get the last sent message
  _user.get('/getLastSentMessage', (req, res) => {
    res.json({ result: lastSentMessage });
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
