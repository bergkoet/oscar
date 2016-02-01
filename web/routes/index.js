var trellodb = require('../lib/trellodb').connect();
var doT = require('express-dot');

exports.learn_barcode = function(req, res){
  if (typeof req.param('item') !== 'undefined') {
    // Learn rule if the item name is included as a parameter in the request
    var rule = {barcode: req.app.locals.opp_data['barcode'],
                item: req.param('item'),
                desc: req.app.locals.opp_data['desc']};

    trellodb.insert('barcode_rules',
                    rule,
                    function() {
                        res.render('thank_barcode', {title: 'Oscar: Learned barcode',
                                                     rule: rule})
                    });
  } else {
    // Send user to form for manually setting item name
    res.render('learn_barcode', {title: 'Oscar: Learn barcode'});
  }
};

exports.submit_learn_barcode = function(req, res){
  var rule = {barcode: req.body['barcode'], item: req.body['item'], desc: req.body['desc']};

  trellodb.insert('barcode_rules',
                  rule,
                  function() {
                      res.render('thank_barcode', {title: 'Oscar: Learned barcode',
                                                   rule: rule})
                  });
};
