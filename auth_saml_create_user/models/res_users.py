# © 2019 Savoir-faire Linux
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

import logging

from odoo import api, models
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class Users(models.Model):
    _inherit = "res.users"

    @api.multi
    def _auth_saml_signin(self, provider, validation, saml_response):
        saml_uid = validation['user_id']
        if self.check_if_create_user(provider):
            self.create_user(saml_uid, provider)
        super()._auth_saml_signin(provider, validation, saml_response)

    def check_if_create_user(self, provider):
        return self.env['auth.saml.provider'].browse(provider).create_user

    def create_user(self, saml_uid, provider):
        _logger.debug("Creating new Odoo user \"%s\" from SAML" % saml_uid)
        SudoUser = self.env['res.users'].sudo()
        new_user = SudoUser.create({
            'name': saml_uid,
            'login': saml_uid,
            'saml_provider_id': provider,
            'company_id': self.env['res.company'].sudo().browse(1).id,
            'saml_uid': saml_uid
        })
        new_user.write({'saml_uid': saml_uid})
