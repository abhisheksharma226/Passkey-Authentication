const express = require("express");
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server')
const crypto = require('node:crypto')

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}


const PORT = 3000;
const app = express();


app.use(express.static("./public"));

app.use(express.json());


const userStore = {};
const challengeStore = {};

app.post("/register" , (req ,res) => {
    const { username , password } = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id, 
        username,
        password 
    }

    userStore[id] = user;

    console.log(`Register Successfully` , userStore[id]);

    return res.json({ id });

})


app.post('/register-challenge' , async (req , res) => {
    const { userId } = req.body;

    if(!userStore[userId]) return res.status(404).json({ error: 'user not found' });

    const user = userStore[userId];

    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My localhost Machine',
        userName: user.username,
    })

    challengeStore[userId] = challengePayload.challenge

    return res.json({ options: challengePayload })

})


app.post('/register-verify' , async(req , res) => {
    const { userId , cred } = req.body;

    if( !userStore[userId]) return res.status(404).json({ error: 'user not found' });

    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if(!verificationResult.verified) return res.json({ error: 'could not verify' });
    userStore[userId].passkey = verificationResult.registrationInfo
    
    return res.json({ verified : true })

})



app.listen(PORT , () => {
    console.log(`Server is running on port ${PORT}`);
})