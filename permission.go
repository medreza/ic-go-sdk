// Copyright 2023 AccelByte Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ic

import "strings"

const (
	resourceUser    = "USER"
	resourceOrg     = "ORG"
	resourceProject = "PROJ"
)

func (client *DefaultClient) permissionAllowed(grantedPermissions []Permission, requiredPermission Permission) bool {
	for _, grantedPermission := range grantedPermissions {
		grantedAction := grantedPermission.Action
		if client.resourceAllowed(grantedPermission.Resource, requiredPermission.Resource) &&
			client.actionAllowed(grantedAction, requiredPermission.Action) {
			return true
		}
	}

	return false
}

func (client *DefaultClient) resourceAllowed(accessPermissionResource string, requiredPermissionResource string) bool {
	requiredPermResSections := strings.Split(requiredPermissionResource, ":")
	requiredPermResSectionLen := len(requiredPermResSections)
	accessPermResSections := strings.Split(accessPermissionResource, ":")
	accessPermResSectionLen := len(accessPermResSections)

	minSectionLen := accessPermResSectionLen
	if minSectionLen > requiredPermResSectionLen {
		minSectionLen = requiredPermResSectionLen
	}

	for i := 0; i < minSectionLen; i++ {
		userSection := accessPermResSections[i]
		requiredSection := requiredPermResSections[i]

		if userSection != requiredSection && userSection != "*" {
			return false
		}
	}

	if accessPermResSectionLen == requiredPermResSectionLen {
		return true
	}

	if accessPermResSectionLen < requiredPermResSectionLen {
		if accessPermResSections[accessPermResSectionLen-1] == "*" {
			if accessPermResSectionLen < 2 {
				return true
			}

			segment := accessPermResSections[accessPermResSectionLen-2]
			if segment == resourceUser || segment == resourceOrg || segment == resourceProject {
				return false
			}

			return true
		}

		return false
	}

	for i := requiredPermResSectionLen; i < accessPermResSectionLen; i++ {
		if accessPermResSections[i] != "*" {
			return false
		}
	}

	return true
}

func (client *DefaultClient) actionAllowed(grantedAction int, requiredAction int) bool {
	return grantedAction&requiredAction == requiredAction
}

func (client *DefaultClient) applyUserPermissionResourceValues(
	grantedPermissions []Permission, claims *JWTClaims, allowedOrganizationID, allowedProjectID string) []Permission {
	for i := range grantedPermissions {
		grantedPermissions[i].Resource = strings.ReplaceAll(
			grantedPermissions[i].Resource, "{userId}", claims.Subject)
		if len(allowedOrganizationID) > 0 {
			grantedPermissions[i].Resource = strings.ReplaceAll(
				grantedPermissions[i].Resource, "{organizationId}", allowedOrganizationID)
		}
		if len(allowedProjectID) > 0 {
			grantedPermissions[i].Resource = strings.ReplaceAll(
				grantedPermissions[i].Resource, "{projectId}", allowedProjectID)
		}
	}
	return grantedPermissions
}
