const express = require('express');
const { models } = require('../database');
const User = models.user;

const router = express.Router();

router.get('/', async function(req, res, next) {
    const users = await User.findAll();
	  res.status(200).json(users);
});

router.get('/:id', async function(req, res, next) {
    try {
        const user = await User.findByPk(req.params.id);
        if (user === null ) {
            res.status(404).json({error: "not found"});
        } else  {
            res.status(200).json(user);
        }

    } catch (err) {
        console.error(`Error while fetching user`, err.message);
        next(err);
    }
});

router.post('/', async function(req, res, next) {
    try {
        const user = await User.create(req.body);
        res.status(201).json(user);
    } catch (err) {
        console.error(`Error while creating user`, err.message);
        next(err);
    }
});

router.put('/:id', async function(req, res, next) {
    try {
        const user = await User.findByPk(req.params.id);
        if (user === null) {
            res.status(404).json({error: "not found"});
        } else {
            await User.update(req.body, { where: { id: req.params.id }});
            await user.reload();
            res.status(200).json(user);
        }
    } catch (err) {
        console.error(`Error while updating user`, err.message);
        next(err);
    }
});

router.delete('/:id', async function(req, res, next) {
    try {
        const user = await User.destroy({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (err) {
        console.error(`Error while deleting user`, err.message);
        next(err);
    }
});

module.exports = router;
