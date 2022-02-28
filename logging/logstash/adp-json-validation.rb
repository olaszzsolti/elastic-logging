
$validationDecodedJsonFieldParamName = "decodedJsonField"
$failTagParamName = "failTag"

def register(param)
    decodedJsonFieldParamName = $validationDecodedJsonFieldParamName
    failTagParamName = $failTagParamName

    logger.debug("Check if parameter #{decodedJsonFieldParamName} is provided")
    if (param[decodedJsonFieldParamName].nil? || param[decodedJsonFieldParamName].empty?)
        raise ArgumentError.new("Parameter \"#{decodedJsonFieldParamName}\" is not provided")
    end

    logger.debug("Check if parameter #{failTagParamName} is provided")
    if (param[failTagParamName].nil? || param[failTagParamName].empty?)
        raise ArgumentError.new("Parameter \"#{failTagParamName}\" is not provided")
    end

    @decodedJsonField = param[decodedJsonFieldParamName]
    @failTag = param[failTagParamName]

    @REQUIRED_FIELDS = ["version", "timestamp", "severity", "service_id", "message"]
    @VALID_FIELDS_VERSION_0_2_0 = @REQUIRED_FIELDS + ["metadata"]
    @VALID_FIELDS_VERSION_0_3_0 = @VALID_FIELDS_VERSION_0_2_0 + ["facility", "subject", "resp_message", "resp_code"]
    @VALID_FIELDS_VERSION_1_0_0 = @VALID_FIELDS_VERSION_0_3_0 + ["extra_data"]
    @VERSION_0_2_0 = "0.2.0"
    @VERSION_0_3_0 = "0.3.0"
    @VERSION_1_0_0 = "1.0.0"
    @VALID_VERSIONS = [@VERSION_0_2_0, @VERSION_0_3_0, @VERSION_1_0_0]
    @VALID_SEVERITIES = ["debug", "info", "warning", "error", "critical"]
    @VALID_METADATA_FIELDS = ["function", "category", "proc_id", "ul_id"]
    # REGEX EXPLAINATION
    # \d{4}\-\d\d\-\d\d     YYYY-MM-DD
    # [T][\d:\.]+           THH:MM:SS
    # ([zZ]|([+\-])(\d\d):?(\d\d)) [zZ] or [+-]DD:DD
    @VALID_TIMESTAMP_REGEX = /^\d{4}\-\d\d\-\d\d[T][\d:\.]+([zZ]|([+\-])(\d\d):?(\d\d))?$/

    def gotRequiredFields(fields)
        @REQUIRED_FIELDS.each do |field|
            if (!fields.include?(field))
                return false
            end
        end

        return true
    end

    def validVersion(version)
        if (version.class != String)
            return false
        end

        return @VALID_VERSIONS.include?(version)
    end

    def validMessage(message)
        if (message.class != String)
            return false
        end

        return true
    end

    def validSeverity(severity)
        if (severity.class != String)
            return false
        end

        return @VALID_SEVERITIES.include?(severity)
    end

    def validServiceId(serviceId)
        if (serviceId.class != String)
            return false
        end

        return true
    end

    def validExtraData(extraData)
        if (extraData.nil?)
            return true
        end

        if (extraData.class != Hash)
            return false
        end

        if (extraData.empty?)
            return false
        end

        return true
    end

    def validMetadata(metadata, version)
        if (metadata.nil?)
            return true
        end

        if (metadata.class != Hash)
            return false
        end

        if (metadata.empty?)
            return false
        end

        case version
        when @VERSION_0_2_0, @VERSION_0_3_0
            if (metadata.keys.length > @VALID_METADATA_FIELDS.length)
                return false
            end

            metadata.keys.each do |key|
                if (!@VALID_METADATA_FIELDS.include?(key))
                    return false
                end

                if (metadata[key].class != String)
                    return false
                end
            end

        when @VERSION_1_0_0
            metadata.keys.each do |key|
                if (metadata[key].class != String)
                    return false
                end
            end
        end

        return true
    end

    def validTimestamp(timestamp)
        if (timestamp.class == LogStash::Timestamp)
            return true
        end

        if (timestamp.class != String)
            return false
        end

        return timestamp =~ @VALID_TIMESTAMP_REGEX
    end

    def validFacility(facility)
        if (!facility.nil? && facility.class != String)
            return false
        end

        return true
    end

    def validSubject(subject)
        if (!subject.nil? && subject.class != String)
            return false
        end

        return true
    end

    def validRespMessage(respMessage)
        if (!respMessage.nil? && respMessage.class != String)
            return false
        end

        return true
    end

    def validRespCode(respCode)
        if (!respCode.nil? && respCode.class != String)
            return false
        end

        return true
    end

    def gotNoAdditionalFields(fields, version)
        case version
        when @VERSION_0_2_0
            return (fields & @VALID_FIELDS_VERSION_0_2_0) == fields
        when @VERSION_0_3_0
            return (fields & @VALID_FIELDS_VERSION_0_3_0) == fields
        when @VERSION_1_0_0
            return (fields & @VALID_FIELDS_VERSION_1_0_0) == fields
        end

        return false
    end

    def addValidationFailureTag(event)
        tags = event.get("tags")

        if (tags.nil?)
            tags = []
        end

        tags.push(@failTag)
        event.set("tags", tags)

        return [event]
    end
end


def filter(event)
    logger.debug("Validate ADP JSON events")

    logger.debug("Check if event got required fields")
    # if (!gotRequiredFields(event.get("#{@decodedJsonField}").keys))
    if (!gotRequiredFields(event.to_hash.keys))
        #logger.warn("Event does not have the required fields")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got valid version")
    # version = event.get("[#{@decodedJsonField}][version]")
    version = event.get("[version]")
    if (!validVersion(version))
        #logger.warn("Event does not have the valid version")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got valid message")
    # if (!validTimestamp(event.get("[#{@decodedJsonField}][message]")))
    if (!validMessage(event.get("[message]")))
        #logger.warn("Event does not have the valid message")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got valid timestamp")
    # if (!validTimestamp(event.get("[#{@decodedJsonField}][timestamp]")))
    if (!validTimestamp(event.get("[timestamp]")))
        #logger.warn("Event does not have a valid timestamp")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got valid severity levels")
    # if (!validSeverity(event.get("[#{@decodedJsonField}][severity]")))
    if (!validSeverity(event.get("[severity]")))
        #logger.warn("Event does not have an valid severity value")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got valid service id")
    # if (!validServiceId(event.get("[#{@decodedJsonField}][service_id]")))
    if (!validServiceId(event.get("[service_id]")))
        #logger.warn("Event does not have an valid service id")
        return addValidationFailureTag(event)
    end

    logger.debug("Check if event got metadata field defined")
    # metadata = event.get("[#{@decodedJsonField}][metadata]")
    metadata = event.get("[metadata]")
    if (!validMetadata(metadata, version))
        #logger.warn("Event does not have an valid metadata field")
        return addValidationFailureTag(event)
    end

    case version
    when @VERSION_0_3_0, @VERSION_1_0_0
        logger.debug("Check if event got facility field defined")
        # if (!validFacility(event.get("[#{@decodedJsonField}][facility]")))
        if (!validFacility(event.get("[facility]")))
            #logger.warn("Event does not have an valid facility field")
            return addValidationFailureTag(event)
        end

        logger.debug("Check if event got subject field defined")
        # if (!validSubject(event.get("[#{@decodedJsonField}][subject]")))
        if (!validSubject(event.get("[subject]")))
            #logger.warn("Event does not have an valid subject field")
            return addValidationFailureTag(event)
        end

        logger.debug("Check if event got resp_message field defined")
        # if (!validRespMessage(event.get("[#{@decodedJsonField}][resp_message]")))
        if (!validRespMessage(event.get("[resp_message]")))
            #logger.warn("Event does not have an valid resp_message field")
            return addValidationFailureTag(event)
        end

        logger.debug("Check if event got resp_code field defined")
        # if (!validSubject(event.get("[#{@decodedJsonField}][resp_code]")))
        if (!validSubject(event.get("[resp_code]")))
            #logger.warn("Event does not have an valid resp_code field")
            return addValidationFailureTag(event)
        end

        if (version == @VERSION_1_0_0)
            logger.debug("Check if event got extraData field defined")
            # extraData = event.get("[#{@decodedJsonField}][extra_data]")
            extraData = event.get("[extra_data]")
            if (!validExtraData(extraData))
                #logger.warn("Event does not have a valid extraData field")
                return addValidationFailureTag(event)
            end
        end
    end

    logger.debug("Check if event got any additional fields then accepted")
    # if (!gotNoAdditionalFields(event.get("#{@decodedJsonField}").keys, version))
    if (!gotNoAdditionalFields(event.to_hash.keys, version))
        #logger.warn("Event does have additional fields that is not accepted")
        return addValidationFailureTag(event)
    end

    logger.debug("Event is in a valid ADP JSON format")
    return [event]
end
