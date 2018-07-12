class User < ApplicationRecord 
  validates :user_name, presence: true, uniqueness: true 
  validates :session_token, presence: true, uniqueness: true 
  before_validation :ensure_session_token
  
  attr_reader :password
  
  def self.find_by_credentials(username, password)
    user = User.find_by(user_name: username)
    return user if user && BCrypt::Password.new(user.password_digest).is_password?(password)
    nil   
  end   
  
  def self.generate_session_token
    SecureRandom::urlsafe_base64(16)
  end
  
  def password=(password)
    @password = password
    self.password_digest = BCrypt::Password.create(@password)
  end
   
  def is_password?(password)
    self.password_digest.is_password?(password)
  end
  
  def reset_session_token! 
    self.session_token = User.generate_session_token 
    self.save!
    self.session_token
  end 
  
  
  def ensure_session_token
    self.session_token ||= User.generate_session_token
  end
end 