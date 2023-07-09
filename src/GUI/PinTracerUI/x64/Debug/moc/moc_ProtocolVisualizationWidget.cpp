/****************************************************************************
** Meta object code from reading C++ file 'ProtocolVisualizationWidget.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/protocol/ProtocolVisualizationWidget.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ProtocolVisualizationWidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS = QtMocHelpers::stringData(
    "ProtocolVisualizationWidget",
    "buttonColorByWordTypeClicked",
    "",
    "buttonColorByPurposeClicked",
    "buttonViewRawProtocolClicked"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS_t {
    uint offsetsAndSizes[10];
    char stringdata0[28];
    char stringdata1[29];
    char stringdata2[1];
    char stringdata3[28];
    char stringdata4[29];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS_t qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS = {
    {
        QT_MOC_LITERAL(0, 27),  // "ProtocolVisualizationWidget"
        QT_MOC_LITERAL(28, 28),  // "buttonColorByWordTypeClicked"
        QT_MOC_LITERAL(57, 0),  // ""
        QT_MOC_LITERAL(58, 27),  // "buttonColorByPurposeClicked"
        QT_MOC_LITERAL(86, 28)   // "buttonViewRawProtocolClicked"
    },
    "ProtocolVisualizationWidget",
    "buttonColorByWordTypeClicked",
    "",
    "buttonColorByPurposeClicked",
    "buttonViewRawProtocolClicked"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSProtocolVisualizationWidgetENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   32,    2, 0x0a,    1 /* Public */,
       3,    0,   33,    2, 0x0a,    2 /* Public */,
       4,    0,   34,    2, 0x0a,    3 /* Public */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject ProtocolVisualizationWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSProtocolVisualizationWidgetENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ProtocolVisualizationWidget, std::true_type>,
        // method 'buttonColorByWordTypeClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'buttonColorByPurposeClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'buttonViewRawProtocolClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void ProtocolVisualizationWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProtocolVisualizationWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->buttonColorByWordTypeClicked(); break;
        case 1: _t->buttonColorByPurposeClicked(); break;
        case 2: _t->buttonViewRawProtocolClicked(); break;
        default: ;
        }
    }
    (void)_a;
}

const QMetaObject *ProtocolVisualizationWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolVisualizationWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSProtocolVisualizationWidgetENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProtocolVisualizationWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 3;
    }
    return _id;
}
QT_WARNING_POP
