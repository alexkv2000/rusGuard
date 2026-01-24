package kvo.rusguard.client;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ArrayOfguid", propOrder = {"ids"})
public class ArrayOfguidWrapper {

    @XmlElement(name = "guid", namespace = "http://schemas.microsoft.com/2003/10/Serialization/Arrays")
    protected List<String> ids;

    public ArrayOfguidWrapper() {}

    public ArrayOfguidWrapper(List<String> ids) {
        this.ids = ids;
    }

    public List<String> getIds() {
        if (ids == null) ids = new ArrayList<>();
        return ids;
    }

    public void setIds(List<String> ids) {
        this.ids = ids;
    }

    // Конвертация в оригинальный ArrayOfguid (если нужно)
    public com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid toOriginal() {
        com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid orig = new com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfguid();
        orig.getGuid().addAll(this.ids);
        return orig;
    }
}