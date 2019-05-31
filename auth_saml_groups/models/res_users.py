# © 2019 Savoir-faire Linux
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

import logging

from odoo import api, models
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)

try:
    import lasso
except ImportError:
    _logger.debug('Cannot `import lasso`.')


class ResUser(models.Model):
    """Add SAML login capabilities to Odoo users.
    """

    _inherit = 'res.users'

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
        for k in attrs:
            if isinstance(k, tuple) and k[0] == matching_attribute:
                matching_value = attrs[k][0]
                break

        if not matching_value and matching_attribute == "subject.nameId":
            matching_value = login.assertion.subject.nameId.content

        elif not matching_value and matching_attribute != "subject.nameId":
            raise Exception(
                "Matching attribute %s not found in user attrs: %s" % (
                    matching_attribute, attrs))
        validation = {'user_id': matching_value}
        return (validation, attrs)

    @api.model
    def auth_saml(self, provider, saml_response):

        saml_validate = self._auth_saml_validate(provider, saml_response)
        validation = saml_validate[0]
        attrs = saml_validate[1]
        # required check
        if not validation.get('user_id'):
            raise AccessDenied()

        # retrieve and sign in user
        login = self._auth_saml_signin(
            provider, validation, saml_response, attrs)

        if not login:
            raise AccessDenied()

        # return user credentials
        return self.env.cr.dbname, login, saml_response

    @api.multi
    def _auth_saml_signin(self, provider, validation, saml_response, attrs):
        """ retrieve and sign into openerp the user corresponding to provider
        and validated access token

            :param provider: saml provider id (int)
            :param validation: result of validation of access token (dict)
            :param saml_response: saml parameters response from the IDP
            :return: user login (str)
            :raise: openerp.exceptions.AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        token_osv = self.env['auth_saml.token']
        saml_uid = validation['user_id']

        user_ids = self.search(
            [('saml_uid', '=', saml_uid), ('saml_provider_id', '=', provider)])

        if user_ids:
            # TODO replace assert by proper raise... asserts do not execute in
            # production code...
            assert len(user_ids) == 1
            user = user_ids[0]

            # now find if a token for this user/provider already exists
            token_ids = token_osv.search(
                [('saml_provider_id', '=', provider), ('user_id', '=', user.id)])

            if token_ids:
                token_ids.write({'saml_access_token': saml_response})
            else:
                token_osv.create({'saml_access_token': saml_response,
                                  'saml_provider_id': provider,
                                  'user_id': user.id
                                  })
            self._set_user_groups(user, provider, attrs)
            return user.login
        elif self.env['auth.saml.provider'].browse(provider).create_user:
            _logger.debug("Creating new Odoo user \"%s\" from SAML" % saml_uid)
            # This following line is to create user with default template
            # values = self.map_saml_attributes(conf, saml_uid, saml_entry)
            SudoUser = self.env['res.users'].sudo()
            # if conf['user']:
            #    values['active'] = True
            #   user_id = SudoUser.browse(conf['user'][0]).copy(default=values).id
            new_user = SudoUser.create({
                'name': saml_uid,
                'login': saml_uid,
                'saml_provider_id': provider,
                'company_id': self.env['res.company'].sudo().browse(1).id,
                'saml_uid': saml_uid
            })
            new_user.write({'saml_uid': saml_uid})
            token_osv.create({'saml_access_token': saml_response,
                              'saml_provider_id': provider,
                              'user_id': new_user.id
                              })
            self._set_user_groups(new_user, provider, attrs)
            return new_user.login
        else:
            raise AccessDenied()

    def _set_user_groups(self, user, provider_id, attrs):
        provider = self.env['auth.saml.provider'].browse(provider_id)
        provider._get_user_groups(user.id, attrs)
