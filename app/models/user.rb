class User < ApplicationRecord
  has_secure_password

  enum :role, { admin: 0, user: 1, driver: 2 }

  validates :email, presence: true, uniqueness: true
end
