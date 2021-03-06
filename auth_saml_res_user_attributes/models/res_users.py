# © 2020 Savoir-faire Linux
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

from odoo import api, models
from odoo.exceptions import AccessDenied
_logger = logging.getLogger(__name__)
try:
    import lasso
except ImportError:
    _logger.debug('Cannot `import lasso`.')


class ResUsers(models.Model):
    _inherit = "res.users"

    @api.multi
    def _auth_saml_validate(self, provider_id, token):
        """ return the validation data corresponding to the access token """

        p = self.env['auth.saml.provider'].browse(provider_id)

        # we are not yet logged in, so the userid cannot have access to the
        # fields we need yet
        login = p.sudo()._get_lasso_for_provider()
        matching_attribute = p._get_matching_attr_for_provider()

        try:
            login.processAuthnResponseMsg(token)
        except (lasso.DsError, lasso.ProfileCannotVerifySignatureError):
            raise Exception('Lasso Profile cannot verify signature')
        except lasso.ProfileStatusNotSuccessError:
            raise Exception('Profile Status Not Success Error')
        except lasso.Error as e:
            raise Exception(repr(e))

        try:
            login.acceptSso()
        except lasso.Error as error:
            raise Exception(
                'Invalid assertion : %s' % lasso.strError(error[0]))

        attrs = {}

        for att_statement in login.assertion.attributeStatement:
            for attribute in att_statement.attribute:
                name = None
                lformat = lasso.SAML2_ATTRIBUTE_NAME_FORMAT_BASIC
                nickname = None
                try:
                    name = attribute.name
                except Exception:
                    _logger.warning('sso_after_response: error decoding name \
                        of attribute %s' % attribute.dump())
                else:
                    if attribute.nameFormat:
                        lformat = attribute.nameFormat
                    if attribute.friendlyName:
                        nickname = attribute.friendlyName
                    if name:
                        if lformat:
                            if nickname:
                                key = (name, lformat, nickname)
                            else:
                                key = (name, lformat)
                        else:
                            key = name
                    attrs[key] = list()
                    for value in attribute.attributeValue:
                        content = [a.exportToXml() for a in value.any]
                        content = ''.join(content)
                        attrs[key].append(content)

        matching_value = None
        matching_name = None
        for k in attrs:
            if isinstance(k, tuple) and k[0] == matching_attribute:
                matching_value = attrs[k][0]
                break
        for k in attrs:
            if isinstance(k, tuple) and k[0] == 'urn:oid:2.16.840.1.113730.3.1.241':
                matching_name = attrs[k][0]
                break

        if not matching_value and matching_attribute == "subject.nameId":
            matching_value = login.assertion.subject.nameId.content

        elif not matching_value and matching_attribute != "subject.nameId":
            raise Exception(
                "Matching attribute %s not found in user attrs: %s" % (
                    matching_attribute, attrs))

        validation = {'user_id': matching_value, 'name': matching_name}
        return (validation, attrs)

    @api.multi
    def _auth_saml_signin(self, provider, validation, saml_response, attr):
        saml_uid = validation['user_id']
        user_ids = self.search(
            [('saml_uid', '=', saml_uid), ('saml_provider_id', '=', provider)])
        if self.check_if_create_user(provider) and not user_ids:
            self.create_user(validation, provider)
        return super()._auth_saml_signin(provider, validation, saml_response, attr)

    def create_user(self, validation, provider):
        saml_uid = validation['user_id']
        name = validation['name']
        _logger.debug("Creating new Odoo user \"%s\" from SAML" % saml_uid)
        SudoUser = self.env['res.users'].sudo()
        new_user = SudoUser.create({
            'name': name,
            'login': saml_uid,
            'saml_provider_id': provider,
            'company_id': self.env['res.company'].sudo().browse(1).id,
        })
        new_user.write({'saml_uid': saml_uid})
