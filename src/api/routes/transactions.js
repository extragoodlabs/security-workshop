const express = require('express');
const { models } = require('../database');
const Transaction = models.transaction;

const router = express.Router();

router.get('/', async function(req, res, next) {
    const transactions = await Transaction.findAll();
	  res.status(200).json(transactions);
});

router.get('/:id', async function(req, res, next) {
    try {
        const transaction = await Transaction.findByPk(req.params.id);
        if (transaction === null ) {
            res.status(404).json({error: "not found"});
        } else  {
            res.status(200).json(transaction);
        }

    } catch (err) {
        console.error(`Error while fetching transaction`, err.message);
        next(err);
    }
});

router.post('/', async function(req, res, next) {
    try {
        const transaction = await Transaction.create(req.body);
        res.status(201).json(transaction);
    } catch (err) {
        console.error(`Error while creating transaction`, err.message);
        next(err);
    }
});

router.put('/:id', async function(req, res, next) {
    try {
        const transaction = await Transaction.findByPk(req.params.id);
        if (transaction === null) {
            res.status(404).json({error: "not found"});
        } else {
            await Transaction.update(req.body, { where: { id: req.params.id }});
            await transaction.reload();
            res.status(200).json(transaction);
        }
    } catch (err) {
        console.error(`Error while updating transaction`, err.message);
        next(err);
    }
});

router.delete('/:id', async function(req, res, next) {
    try {
        const transaction = await Transaction.destroy({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (err) {
        console.error(`Error while deleting transaction`, err.message);
        next(err);
    }
});

module.exports = router;
