// Copyright 2017 Bryan Jeal <bryan@jeal.ca>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import uuid "github.com/satori/go.uuid"

// Group is an organizational unit that Users can belong to.
// Provides an easy way to apply the same permissions to multiple users
type Group struct {
	ID          uuid.UUID
	Name        string
	Slug        string
	Permissions []Permission
}
