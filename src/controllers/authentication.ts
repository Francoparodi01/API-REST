import  express  from "express";

import { createUser, getUserByEmail} from "../db/users";
import { authentication, random } from "../helpers";

export const login = async (req: express.Request, res: express.Response) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.sendStatus(400); // Bad Request
        }

        // Fetch the user and include authentication fields
        const user = await getUserByEmail(email).select('+authentication.password +authentication.salt');
        if (!user || !user.authentication) {
            return res.sendStatus(400); // Bad Request
        }

        // Check if the authentication object has required properties
        const { salt, password: storedPassword } = user.authentication;
        if (!salt || !storedPassword) {
            return res.sendStatus(400); // Bad Request
        }

        const expectedHash = authentication(salt, password);
        if (storedPassword !== expectedHash) {
            return res.sendStatus(403); // Forbidden
        }

        const newSalt = random();
        user.authentication.sessionToken = authentication(newSalt, user._id.toString());

        await user.save();
        res.cookie('FRANCO-AUTH', user.authentication.sessionToken, { domain: 'localhost', path: '/' });

        return res.status(200).json(user).end();
    } catch (error) {
        console.error("Error during login:", error);
        return res.sendStatus(500); // Internal Server Error
    }
};

export const register = async (req:express.Request, res: express.Response) => {
    try {
        // Esto lo encuentra en nuestro schema y lo trae con la request.
        const {email, password, username} = req.body

        if (!email || !password || !username) {
            return res.sendStatus(400)
        }

        const existingUser = await getUserByEmail(email);

        if (existingUser){
            return res.sendStatus(400)
        }

        const salt = random();
        const user = await createUser({
            email, 
            username,
            authentication:{
                salt,
                password: authentication(salt, password), 
            },
        });

        return res.status(200).json(user).end()

    } catch (error) {
        console.log(error)
        return res.sendStatus(400)
    }
}

