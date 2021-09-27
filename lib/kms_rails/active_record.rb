require 'msgpack'
require 'kms_rails/core'

module KmsRails
  module ActiveRecord
    class << self
      def included base
        base.extend ClassMethods
      end
    end
    
    module ClassMethods
      def kms_attr(field, key_id:, retain: false, msgpack: false, context_key: nil, context_value: nil, aws_client: nil)
        include InstanceMethods

        real_field = "#{field}_enc"
        enc        = Core.new(key_id: key_id, msgpack: msgpack, context_key: context_key, context_value: context_value)

        define_method "#{field}=" do |data|
          raise RuntimeError, "Field '#{field}' must not be a real column, '#{real_field}' is the real column" if self.class.column_names.include?(field.to_s)
          raise RuntimeError, "Field '#{real_field}' must exist to store encrypted data" unless self.class.column_names.include?(real_field)

          if data.blank? # Just set to nil if nil
            clear_retained(field)
            self[real_field] = nil
            return 
          end

          set_retained(field, data) if retain
          encrypted_data = enc.encrypt(data, evaluate_key_id(key_id, self), evaluate_aws_client(aws_client, self))
          data = nil
          
          store_hash(field, encrypted_data)
        end

        define_method "#{real_field}" do
          raise RuntimeError, "Field '#{field}' must not be a real column, '#{real_field}' is the real column" if self.class.column_names.include?(field.to_s)
          raise RuntimeError, "Field '#{real_field}' must exist to retrieve encrypted data" unless self.class.column_names.include?(real_field)
          Core.to64( get_hash(field) )
        end

        define_method "#{field}" do
          raise RuntimeError, "Field '#{field}' must not be a real column, '#{real_field}' is the real column" if self.class.column_names.include?(field.to_s)
          raise RuntimeError, "Field '#{real_field}' must exist to retrieve decrypted data" unless self.class.column_names.include?(real_field)

          hash = get_hash(field)
          return nil unless hash

          if retain && (plaintext = get_retained(field))
            plaintext
          else
            plaintext = enc.decrypt(hash)
            set_retained(field, plaintext) if retain
            plaintext
          end
        end

        define_method "#{field}_clear" do
          clear_retained(field)
        end

      end
    end

    module InstanceMethods
      def store_hash(field, data)
        self["#{field}_enc"] = data.to_msgpack
      end

      def evaluate_key_id(base_key_id, object)
        case base_key_id
        when Proc
          object.instance_eval &base_key_id
        when String
          if base_key_id =~ /\A\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\z/ || base_key_id.start_with?('alias/') # if UUID or direct alias
            KmsRails.configuration.arn_prefix + base_key_id
          else
            KmsRails.configuration.arn_prefix + 'alias/' + KmsRails.configuration.alias_prefix + base_key_id
          end
        else
          raise RuntimeError, 'Only Proc and String arguments are supported'
        end
      end

      def evaluate_aws_client(base_value, object)
        case base_value
        when nil
          nil
        when Proc
          object.instance_eval &base_value
        when Aws::S3::Client
          base_value
        else
          raise RuntimeError, 'Only Proc and Aws::S3::Client arguments are supported'
        end
      end

      def get_hash(field)
        hash = read_attribute("#{field}_enc")
        hash ? MessagePack.unpack(hash) : nil
      end

      def get_retained(field)
        @_retained ||= {}
        @_retained[field]
      end

      def set_retained(field, plaintext)
        @_retained ||= {}

        if @_retained[field]
          Core.shred_string(@_retained[field]) if @_retained[field].class == String
          @_retained[field] = nil
        end

        @_retained[field] = plaintext.dup
      end

      def clear_retained(field)
        @_retained ||= {}
        return if !@_retained.include?(field) || @_retained[field].nil?
        Core.shred_string(@_retained[field]) if @_retained[field].class == String
        @_retained[field] = nil
      end
    end
  end
end

if Object.const_defined?('ActiveRecord')
  ActiveRecord::Base.send(:include, KmsRails::ActiveRecord)
end
