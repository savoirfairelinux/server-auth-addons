# © 2019 Savoir-faire Linux
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).
from odoo import api, models


class AuthSamlProviderOperator(models.AbstractModel):
    """Define operators for group mappings"""

    _name = "auth.saml.provider.operator"

    @api.model
    def operators(self):
        """Return names of function to call on this model as operator"""
        return ('contains', 'equals')

    def contains(self, saml_entry, mapping):
        return mapping.saml_attribute in saml_entry[1] and \
            mapping.value in map(
                lambda x: x.decode(),
                saml_entry[1][mapping.saml_attribute]
        )

    def equals(self, attrs, mapping):
        matching_value = ''
        for k in attrs:
            if isinstance(k, tuple) and k[0] == mapping.saml_attribute:
                matching_value = attrs[k][0]
                break
        return mapping.value == matching_value
