"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.register = exports.login = void 0;
const users_1 = require("../db/users");
const helpers_1 = require("../helpers");
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.sendStatus(400); // Bad Request
        }
        // Fetch the user and include authentication fields
        const user = yield (0, users_1.getUserByEmail)(email).select('+authentication.password +authentication.salt');
        if (!user || !user.authentication) {
            return res.sendStatus(400); // Bad Request
        }
        // Check if the authentication object has required properties
        const { salt, password: storedPassword } = user.authentication;
        if (!salt || !storedPassword) {
            return res.sendStatus(400); // Bad Request
        }
        const expectedHash = (0, helpers_1.authentication)(salt, password);
        if (storedPassword !== expectedHash) {
            return res.sendStatus(403); // Forbidden
        }
        const newSalt = (0, helpers_1.random)();
        user.authentication.sessionToken = (0, helpers_1.authentication)(newSalt, user._id.toString());
        yield user.save();
        res.cookie('FRANCO-AUTH', user.authentication.sessionToken, { domain: 'localhost', path: '/' });
        return res.status(200).json(user).end();
    }
    catch (error) {
        console.error("Error during login:", error);
        return res.sendStatus(500); // Internal Server Error
    }
});
exports.login = login;
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // Esto lo encuentra en nuestro schema y lo trae con la request.
        const { email, password, username } = req.body;
        if (!email || !password || !username) {
            return res.sendStatus(400);
        }
        const existingUser = yield (0, users_1.getUserByEmail)(email);
        if (existingUser) {
            return res.sendStatus(400);
        }
        const salt = (0, helpers_1.random)();
        const user = yield (0, users_1.createUser)({
            email,
            username,
            authentication: {
                salt,
                password: (0, helpers_1.authentication)(salt, password),
            },
        });
        return res.status(200).json(user).end();
    }
    catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
});
exports.register = register;
