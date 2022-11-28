/*****************************************************************************
 * Import package                                                            *
 *****************************************************************************/
import express = require ('express');
import {Request, Response} from 'express';
import {User} from './user';
import {Connection, MysqlError, OkPacket} from "mysql";
import mysql = require ("mysql");      // handles database connections
import session = require ("express-session");
import crypto = require("crypto")

const database: Connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'userman'
});

/*****************************************************************************
 * Define and start web-app server, define json-Parser                       *
 *****************************************************************************/
const app = express();
app.listen(8080, () => {
    console.log('Server started: http://localhost:8080');
    //---- connect to database ----------------------------------------------------
    database.connect((err: MysqlError) => {
        if (err) {
            console.log('Database connection failed: ', err);
        } else {
            console.log('Database is connected');
        }
    });
});
app.use(express.json());
/*****************************************************************************
 * session management configuration                                          *
 *****************************************************************************/
app.use(session({
    // save session even if not modified
    resave: true,
    // save session even if not used
    saveUninitialized: true,
    // forces cookie set on every response needed to set expiration (maxAge)
    rolling: true,
    // encrypt session-id in cookie using "secret" as modifier
    secret: "geheim",
    // name of the cookie set is set by the server
    name: "mySessionCookie",
    // set some cookie-attributes. Here expiration-date (offset in ms)
    cookie: { maxAge: 1 * 60 * 1000 * 60}
}));

declare module 'express-session' {
    interface SessionData {
        user: User
    }
}



/*****************************************************************************
 * STATIC ROUTES                                                             *
 *****************************************************************************/
const basedir: string = __dirname + '/../..';  // get rid of /server/src
app.use('/', express.static(basedir + '/client'));
app.use('/src', express.static(basedir + '/client/src'));
app.use('/bootstrap', express.static(basedir + '/client/node_modules/bootstrap/dist'));
app.use('/fontawesome', express.static(basedir + '/client/node_modules/@fortawesome/fontawesome-free/css'));
app.use('/webfonts', express.static(basedir + '/client/node_modules/@fortawesome/fontawesome-free/webfonts'));

/**
 * @apiDefine SessionExpired
 *
 * @apiError (Client Error) {401} SessionNotFound The session of the user is expired or was not set
 *
 * @apiErrorExample SessionNotFound:
 * HTTP/1.1 401 Unauthorized
 * {
 *     "message":"Session expired, please log in again."
 * }
 */
function isLoggedIn() {
    // Abstract middleware route for checking login state of the user
    return (req: Request, res: Response, next) => {
        if (req.session.user) {
            // User has an active session and is logged in, continue with route
            next();
        } else {
            // User is not logged in
            res.status(401).send({
                message: 'Session expired, please log in again',
            });
        }
    };
}

/*****************************************************************************
 * HTTP ROUTES: LOGIN                                                        *
 *****************************************************************************/
/**
 * @api {get} /login Request login state
 * @apiName GetLogin
 * @apiGroup Login
 *
 * @apiSuccess {User} user The user object
 * @apiSuccess {string} message Message stating that the user is still logged in
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "user":{
 *         "id":1,
 *         "username":"admin",
 *         "givenName":"Peter",
 *         "familyName":"Kneisel",
 *         "creationTime":"2017-11-12T09:33:25.000Z"
 *      },
 *      "message":"User still logged in"
 *  }
 *
 * @apiError (Client Error) {401} SessionNotFound The session of the user is expired or was not set
 *
 * @apiErrorExample SessionNotFound:
 * HTTP/1.1 401 Unauthorized
 * {
 *     "message":"Session expired, please log in again."
 * }
 */
app.get('/login', isLoggedIn(), (req: Request, res: Response) => {
    res.status(200).send({
        message: 'User still logged in',
        user: req.session.user, // Send user object to client for greeting message
    });
});


/**
 * @api {post} /login Send login request
 * @apiName PostLogin
 * @apiGroup Login
 *
 * @apiBody {string} username Username of the user to log in
 * @apiBody {string} password Password of the user to log in
 *
 * @apiSuccess {User} user The user object
 * @apiSuccess {string} message Message stating the user logged in successfully
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "user":{
 *         "id":1,
 *         "username":"admin",
 *         "givenName":"Peter",
 *         "familyName":"Kneisel",
 *         "creationTime":"2017-11-12T09:33:25.000Z"
 *     },
 *     "message":"Successfully logged in"
 * }
 *
 * @apiError (Client Error) {401} LoginIncorrect The login data provided is not correct.
 * @apiError (Server Error) {500} DatabaseRequestFailed The request to the database failed.
 *
 * @apiErrorExample LoginIncorrect:
 * HTTP/1.1 401 Unauthorized
 * {
 *     "message":"Username or password is incorrect."
 * }
 *
 *
 * @apiErrorExample DatabaseRequestFailed:
 * HTTP/1.1 500 Internal Server Errror
 * {
 *     "message":"Database request failed: ..."
 * }
 */
app.post('/login', (req: Request, res: Response) => {
    // Read data from request
    const username: string = req.body.username;
    const password: string = req.body.password;

    // Create database query and data
    const data: [string, string] = [username, crypto.createHash("sha512").update(password).digest('hex')];
    const query: string = 'SELECT * FROM userlist WHERE username = ? AND password = ?;';

    // request user from database
    database.query(query, data, (err: MysqlError, rows: any) => {
        if (err) {
            // Login data is incorrect, user is not logged in
            res.status(500).send({
                message: 'Database request failed: ' + err,
            });
        } else {
            // Check if database response contains exactly one entry
            if (rows.length === 1) {
                // Login data is correct, user is logged in
                const user: User = {
                    id: rows[0].id,
                    username: rows[0].username,
                    givenName: rows[0].givenName,
                    familyName: rows[0].familyName,
                    creationTime: rows[0].time
                };
                req.session.user = user; // Store user object in session for authentication
                res.status(200).send({
                    message: 'Successfully logged in',
                    user, // Send user object to client for greeting message
                });
            } else {
                // Login data is incorrect, user is not logged in
                res.status(401).send({
                    message: 'Username or password is incorrect.',
                });
            }
        }
    });
});

/**
 * @api {post} /logout Logout user
 * @apiName PostLogout
 * @apiGroup Logout
 *
 * @apiSuccess {string} message Message stating that the user is logged out
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     message: "Successfully logged out"
 * }
 */
app.post('/logout', (req: Request, res: Response) => {
    // Log out user
    delete req.session.user; // Delete user from session
    res.status(200).send({
        message: 'Successfully logged out',
    });
});

/*****************************************************************************
 * HTTP ROUTES: USER, USERS                                                  *
 *****************************************************************************/
/**
 * @api {post} /user Create a new user
 * @apiName postUser
 * @apiGroup User
 *
 * @apiBody {string} givenName First name of the user
 * @apiBody {string} familyName Last name of the user
 *
 * @apiSuccess {string} message Message stating the new user has been created successfully
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "message":"Successfully created new user"
 * }
 *
 * @apiError (Client Error) {400} NotAllMandatoryFields The request did not contain all mandatory fields
 *
 * @apiErrorExample NotAllMandatoryFields:
 * HTTP/1.1 400 Bad Request
 * {
 *     "message":"Not all mandatory fields are filled in"
 * }
 */
app.post('/user', isLoggedIn(), (req: Request, res: Response) => {
    // Read data from request body
    const username: string = req.body.username;
    const password: string = req.body.password;
    const givenName: string = req.body.givenName;
    const familyName: string = req.body.familyName;
    // add a new user if first- and familyName exist
    if (username && password && givenName && familyName) {
        const data: [string, string, string, string, string] = [
            username,
            crypto.createHash("sha512").update(password).digest('hex'),
            givenName,
            familyName,
            new Date().toLocaleString()];
        const query: string = 'INSERT INTO userlist (username, password, givenName, familyName, creationTime) VALUES (?, ?, ?, ?, ?);';
        // Execute database query
        database.query(query, data, (err: MysqlError, result: OkPacket) => {
            if (err || result === null) {
                // Send response
                res.status(400).send({
                    message: 'An error occured while creating the new user',
                });
            } else {
                res.status(201).send({
                    message: 'Successfully created new user',
                });
            }
        });
    } else {
        res.status(400).send({
            message: 'Not all mandatory fields are filled in',
        });
    }
});

/**
 * @api {get} /user/:userId Get user with given id
 * @apiName getUser
 * @apiGroup User
 *
 * @apiParam {number} userId The id of the requested user
 *
 * @apiSuccess {User} user The requested user object
 * @apiSuccess {string} message Message stating the user has been found
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "user":{
 *         "id":1,
 *         "givenName":"Peter",
 *         "familyName":"Kneisel",
 *         "creationTime":"2018-10-21 14:19:12"
 *     },
 *     "message":"Successfully got user"
 * }
 *
 *  @apiError (Client Error) {404} NotFound The requested user can not be found
 *
 * @apiErrorExample NotFound:
 * HTTP/1.1 404 Not Found
 * {
 *     "message":"The requested user can not be found."
 * }
 */
app.get('/user/:userId', isLoggedIn(), (req: Request, res: Response) => {
    // Read data from request parameters
    const userId: number = Number(req.params.userId);
    // Search user in database
    const query: string = 'SELECT * FROM userlist WHERE id = ?;';

    database.query(query, userId, (err: MysqlError, rows: any[]) => {
        if (err) {
            // Database operation has failed
            res.status(500).send({
                message: 'Database request failed: ' + err
            });
        } else {
            if (rows.length === 1) {
                const user: User = {
                    id: rows[0].id,
                    username: rows[0].username,
                    givenName: rows[0].givenName,
                    familyName: rows[0].familyName,
                    creationTime: rows[0].time
                };

                // Send user list to client
                res.status(200).send({
                    user,
                    message: 'Successfully got user',
                });
            } else {
                res.status(404).send({
                    message: 'The requested user can not be found.',
                });
            }
        }
    });
});

/**
 * @api {put} /user/:userId Update user with given id
 * @apiName putUser
 * @apiGroup User
 *
 * @apiParam {number} userId The id of the requested user
 * @apiBody {string} givenName The (new) first name of the user
 * @apiBody {string} familyName The (new) last name of the user
 *
 * @apiSuccess {string} message Message stating the user has been updated
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "message":"Successfully updated user ..."
 * }
 *
 * @apiError (Client Error) {400} NotAllMandatoryFields The request did not contain all mandatory fields
 * @apiError (Client Error) {404} NotFound The requested user can not be found
 *
 * @apiErrorExample NotAllMandatoryFields:
 * HTTP/1.1 400 Bad Request
 * {
 *     "message":"Not all mandatory fields are filled in"
 * }
 *
 * @apiErrorExample NotFound:
 * HTTP/1.1 404 Not Found
 * {
 *     "message":"The user to update could not be found"
 * }
 */
app.put('/user/:userId', isLoggedIn(), (req: Request, res: Response) => {
    // Read data from request
    const userId: number = Number(req.params.userId);
    const givenName: string = req.body.givenName;
    const familyName: string = req.body.familyName;
    // Check that all arguments are given
    if (givenName && familyName) {
        // Create database query and data
        const data: [string, string, number] = [givenName, familyName, userId];
        const query: string = 'UPDATE userlist SET givenName = ?, familyName = ? WHERE id = ?;';

        // Execute database query
        database.query(query, data, (err: MysqlError, result: OkPacket) => {
            if (err || result.affectedRows != 1) {
                res.status(400).send({
                    message: 'The user to update could not be found',
                });
            } else {
                res.status(200).send({
                    message: `Successfully updated user ${givenName} ${familyName}`,
                });
            }
        });
    } else {
        res.status(400).send({
            message: 'Not all mandatory fields are filled in',
        });
    }
});

/**
 * @api {delete} /user/:userId Delete user with given id
 * @apiName deleteUser
 * @apiGroup User
 *
 * @apiParam {number} userId The id of the requested user
 *
 * @apiSuccess {string} message Message stating the user has been updated
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *     "message":"Successfully deleted user ..."
 * }
 */
app.delete('/user/:userId', isLoggedIn(), (req: Request, res: Response) => {
    // Read data from request
    const userId: number = Number(req.params.userId);
    // Delete user
    const query: string = 'DELETE FROM userlist WHERE id = ?;';

    database.query(query, userId, (err: MysqlError, result: OkPacket) => {
        if (err) {
            // Database operation has failed
            res.status(500).send({
                message: 'Database request failed: ' + err
            });
        } else {
            // Check if database response contains at least one entry
            if (result.affectedRows === 1) {
                res.status(200).send({
                    message: `Successfully deleted user `,
                });
            } else {
                res.status(400).send({
                    message: 'The user to be deleted could not be found',
                });
            }
        }
    });
});

/**
 * @api {get} /users Get all users
 * @apiName getUsers
 * @apiGroup Users
 *
 * @apiSuccess {User[]} userList The list of all users
 * @apiSuccess {string} message Message stating the users have been found
 *
 * @apiSuccessExample Success-Response:
 * HTTP/1.1 200 OK
 * {
 *    "userList": [
 *      {
 *        "givenName": "Hans",
 *        "familyName": "Mustermann",
 *        "creationTime": "2018-11-04T13:02:44.791Z",
 *        "id": 1
 *     },
 *      {
 *        "givenName": "Bruce",
 *        "familyName": "Wayne",
 *        "creationTime": "2018-11-04T13:03:18.477Z",
 *        "id": 2
 *      }
 *    ]
 *    "message":"Successfully requested user list"
 * }
 */
app.get('/users', isLoggedIn(), (req: Request, res: Response) => {
    // Send user list to client
    const query: string = 'SELECT * FROM userlist;';

    database.query(query, (err: MysqlError, rows: any[]) => {
        if (err) {
            // Database operation has failed
            res.status(500).send({
                message: 'Database request failed: ' + err
            });
        } else {
            // Create local user list to parse users from database
            const userList: User[] = [];
            // Parse every entry
            for (const row of rows) {
                const user: User = {
                    id: row.id,
                    username: row.username,
                    givenName: row.givenName,
                    familyName: row.familyName,
                    creationTime: row.creationTime
                };
                userList.push(user);
            }

            // Send user list to client
            res.status(200).send({
                userList: userList,
                message: 'Successfully requested user list'
            });
        }
    });
});

