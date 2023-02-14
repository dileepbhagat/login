package com.dor.login.model;

import javax.persistence.Id;
import javax.persistence.MappedSuperclass;

import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import io.hypersistence.utils.hibernate.type.array.IntArrayType;
import io.hypersistence.utils.hibernate.type.array.StringArrayType;

@TypeDefs({
    @TypeDef(
        name = "string-array", 
        typeClass = StringArrayType.class
    ),
    @TypeDef(
        name = "int-array", 
        typeClass = IntArrayType.class
    )
})
@MappedSuperclass
public class BaseEntity {
	
}

