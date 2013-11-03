package com.timepoorprogrammer.saml.core;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * SAML base library abstract class which handles whole library initialisation
 *
 * @author Jim Ball
 */
public abstract class AbstractSAMLHandler {
    private static final Logger log = LoggerFactory.getLogger(AbstractSAMLHandler.class);
    protected static final int DEFAULT_BEFORE_SECONDS = 5;
    protected static final int DEFAULT_TIME_TO_LIVE = 30;
    public static BasicParserPool parserPoolManager;
    /**
     * Any use of this class ensures that the OpenSAML library is bootstrapped once only, and
     * that an ID generator is created for any created SAML objects that need the "correct"
     * format unique identifiers, and so we use a pooled document parser to avoid poor XML
     * and document parsing performance, and finally so we are setup to cope with SAML that
     * is in 1.1 to 2.0 syntax, but NOT SAML 1.0.
     */
    static {
        try {
            DefaultBootstrap.bootstrap();
            Schema schema = SAMLSchemaBuilder.getSAML11Schema();
            parserPoolManager = new BasicParserPool();
            parserPoolManager.setNamespaceAware(true);
            parserPoolManager.setIgnoreElementContentWhitespace(true);
            parserPoolManager.setSchema(schema);
        }
        catch (Exception anyE) {
            final String errorMessage = "Error initialising OpenSAML library";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Create SAML objects on the basis of their QName or type
     *
     * @param qname QName or type
     * @return XMLObject that can be cast to a SAMLObject type
     */
    public XMLObject create(QName qname) {
        try {
            return (Configuration.getBuilderFactory().getBuilder(qname).buildObject(qname));
        } catch (Exception anyE) {
            final String errorMessage = "Error creating XMLObject";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to add an XMLObject as a child of a DOM Element.
     *
     * @param object XMLObject
     * @param parent parent
     * @return DOM element
     */
    public static Element addToElement(XMLObject object, Element parent) {
        try {
            Marshaller out = Configuration.getMarshallerFactory().getMarshaller(object);
            return out.marshall(object, parent);
        } catch (Exception anyE) {
            final String errorMessage = "Error adding XMLObject to element";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to get an XMLObject as a DOM Document.
     *
     * @param object XML object
     * @return document
     */
    public Document asDOMDocument(XMLObject object) {
        try {
            Document document = parserPoolManager.getBuilder().newDocument();
            Marshaller out = Configuration.getMarshallerFactory().getMarshaller(object);
            out.marshall(object, document);
            return document;
        } catch (Exception anyE) {
            final String errorMessage = "Error returning XMLObject as a DOM document";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to pretty-print any XML object to a file or to log.
     *
     * @param object   object
     * @param filename filename or null (meaning write to log)
     */
    public void printToFile(XMLObject object, String filename) {
        try {
            PrettyPrintHelper.printToFile(asDOMDocument(object), filename);
        } catch (Exception anyE) {
            final String errorMessage = "Error pretty printing contents of XMLObject to file";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to print any XML object to an output stream as it is.
     *
     * @param object  object
     * @param oStream OuptutStream to write to
     */
    public void printToStream(XMLObject object, OutputStream oStream) {
        try {
            // Transform the XMLObject into a ByteArrayOutputStream result
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(asDOMDocument(object)), new StreamResult(buffer));
            // Write said ByteArrayOutput content down the wire
            oStream.write(buffer.toByteArray());
            // Close our buffer holding the transformed result
            buffer.close();
        } catch (Exception anyE) {
            final String errorMessage = "Error writing contents of XMLObject to stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to pretty-print any XML object to a String.
     *
     * @param object object
     * @return String pretty representation of object
     */
    public String printToString(XMLObject object) {
        try {
            return PrettyPrintHelper.prettyPrint(asDOMDocument(object));
        } catch (Exception anyE) {
            final String errorMessage = "Error pretty printing contents of XMLObject to String";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to read an XML object from a DOM element.
     *
     * @param element DOM element
     * @return XML object
     */
    public static XMLObject fromElement(Element element) {
        try {
            return Configuration.getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
        } catch (Exception anyE) {
            final String errorMessage = "Error reading XML object from DOM";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to read an XML object from a file.
     *
     * @param filename filename
     * @return XMLObject
     */
    public XMLObject readFromFile(String filename) {
        try {
            return fromElement(parserPoolManager.getBuilder().parse(filename).getDocumentElement());
        } catch (Exception anyE) {
            final String errorMessage = "Error reading XMLObject from file";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }

    /**
     * Helper method to read an XML object from an input stream
     *
     * @param io input stream
     * @return XMLObject
     */
    public XMLObject readFromStream(final InputStream io) {
        try {
            return fromElement(parserPoolManager.getBuilder().parse(io).getDocumentElement());
        } catch (Exception anyE) {
            final String errorMessage = "Error reading XMLObject from stream";
            log.error(errorMessage, anyE);
            throw new RuntimeException(errorMessage, anyE);
        }
    }
}